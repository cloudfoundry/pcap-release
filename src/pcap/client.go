package pcap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"code.cloudfoundry.org/bytefmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const logProgressWait = 5 * time.Second

type MessageWriter interface {
	WriteMessage(message *Message)
}

type LogMessageWriter struct {
	Log *zap.Logger
}

// WriteMessage accepts a Message and writes a log-line using a log-level corresponding to the severity of the message.
func (c LogMessageWriter) WriteMessage(message *Message) {
	formattedMessage := fmt.Sprintf("%s(%s): %s", message.Origin, message.Type, message.Message)
	c.Log.Log(MessageLogLevel(message), formattedMessage)
}

// MessageLogLevel translates the message types to appropropriate default log levels.
func MessageLogLevel(message *Message) zapcore.Level {
	switch message.Type {
	case MessageType_UNKNOWN:
		return zapcore.WarnLevel
	case MessageType_INSTANCE_UNAVAILABLE:
		return zapcore.WarnLevel
	case MessageType_START_CAPTURE_FAILED:
		return zapcore.WarnLevel
	case MessageType_INVALID_REQUEST:
		return zapcore.ErrorLevel
	case MessageType_CONGESTED:
		return zapcore.WarnLevel
	case MessageType_LIMIT_REACHED:
		return zapcore.WarnLevel
	case MessageType_CAPTURE_STOPPED:
		return zapcore.InfoLevel
	case MessageType_CONNECTION_ERROR:
		return zapcore.ErrorLevel
	}
	return zapcore.ErrorLevel
}

// Client provides a reusable client for issuing capture requests against the pcap-api.
type Client struct {
	packetFile    *os.File
	log           *zap.Logger
	stream        API_CaptureClient
	messageWriter MessageWriter
	stopped       bool
	aPIClient
}

// NewClient sets up logging for the client and creates the outputFile.
// It assumes that the outputFile does not pre-exist and that the path is writeable (should be checked by CLI).
//
// NewClient returns a new Client if there are no issues with outputFile creation.
func NewClient(outputFile string, logger *zap.Logger, writer MessageWriter) (*Client, error) {
	var err error

	client := &Client{log: logger, messageWriter: writer}

	if len(outputFile) == 0 {
		if logsToStdout(zapConfig) {
			return nil, fmt.Errorf("writing and logging to stdout is not supported")
		}
		client.packetFile = os.Stdout
	} else {
		client.packetFile, err = os.Create(outputFile)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

func (c *Client) Stop() {
	c.StopRequest()
}

// ConnectToAPI sets up the grpc-connection between client and pcap-api.
//
// Depending on the http scheme in apiURL, it uses plain HTTP or TLS.
func (c *Client) ConnectToAPI(apiURL *url.URL, skipVerify bool) error {
	var (
		err   error
		creds credentials.TransportCredentials
	)

	if apiURL.Scheme == "https" {
		tlsConfig := newTLSConfig()
		tlsConfig.InsecureSkipVerify = skipVerify
		creds = credentials.NewTLS(tlsConfig)
	} else { // plain http
		creds = insecure.NewCredentials()
	}

	c.cc, err = grpc.Dial(apiURL.Host, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("could not connect to pcap-api %q", apiURL)
	}

	return nil
}

func (c *Client) CaptureRequest(endpointRequest *EndpointRequest, options *CaptureOptions) error {
	// set up capture request
	ctx, cancel := context.WithCancelCause(context.Background())

	// perform capture request
	err := c.ProcessCapture(ctx, endpointRequest, options, cancel)
	if err != nil {
		return fmt.Errorf("encountered error during request handling: %w", err)
	}

	// handle results of capture request
	cause := context.Cause(ctx)
	if cause != nil && !errors.Is(cause, context.Canceled) {
		return fmt.Errorf("finished with error: %w", cause)
	}
	return nil
}

// ProcessCapture takes care of the complete lifecycle for a capture request.
// It writes the pcap-header to the outputFile, sends the CaptureRequest to the pcap-api
// and handles the cleanup after the capture is done.
//
// It then delegates writing individual packets and logging messages from the api to ReadCaptureResponse.
// logProgress is called in another goroutine to asynchronously announce on stderr how many bytes were
// already written to the outputFile.
func (c *Client) ProcessCapture(ctx context.Context, endpointRequest *EndpointRequest, options *CaptureOptions, cancel context.CancelCauseFunc) error {
	logger := c.log.With(zap.String(LogKeyHandler, "ProcessCapture"))
	if endpointRequest == nil {
		return fmt.Errorf("endpoint request must not be nil: %w", errInvalidPayload)
	}

	if options == nil {
		return fmt.Errorf("capture options request must not be nil: %w", errInvalidPayload)
	}
	// setup output/pcap-file
	packetWriter := pcapgo.NewWriter(c.packetFile)
	err := packetWriter.WriteFileHeader(options.SnapLen, layers.LinkTypeEthernet)
	if err != nil {
		return err
	}

	captureRequest := &CaptureRequest{
		Operation: &CaptureRequest_Start{
			Start: &StartCapture{
				Request: endpointRequest,
				Options: options,
			},
		},
	}

	c.stream, err = c.Capture(ctx)
	if err != nil {
		return err
	}

	err = c.stream.Send(captureRequest)
	if err != nil {
		return err
	}

	done := c.ReadCaptureResponse(c.stream, packetWriter, cancel)

	go c.logProgress(ctx, logger)

	// wait for progress to finish
	<-ctx.Done()

	logger.Info("waiting for capture to finish")
	// wait for the ReadCaptureResponse goroutine to finish.
	<-done

	logger.Debug("syncing file to disk")
	err = c.packetFile.Sync()
	if err != nil {
		return err
	}

	logger.Debug("closing file")
	err = c.packetFile.Close()
	if err != nil {
		return err
	}

	return nil
}

// logsToStdout determines if the config logs data to stdout.
func logsToStdout(config zap.Config) bool {
	for _, path := range config.OutputPaths {
		// "stdout" has a special meaning in zap and refers to os.Stdout.
		if path == "stdout" {
			return true
		}
	}

	return false
}

func (c *Client) StopRequest() {
	if c.stream == nil {
		c.log.Error("client not connected, could not stop")
		return
	}
	if c.stopped {
		return
	}

	err := c.stream.SendMsg(MakeStopRequest())
	if err != nil {
		c.log.Error("could not stop")
	}
	c.stopped = true
}

// ReadCaptureResponse reads CaptureResponse's from the api in a loop and delegates writing/logging messages & packets to WriteMessage / writePacket.
//
// It terminates if an error or clean stop-message is received.
func (c *Client) ReadCaptureResponse(stream API_CaptureClient, packetWriter *pcapgo.Writer, cancel context.CancelCauseFunc) chan struct{} {
	logger := c.log.With(zap.String(LogKeyHandler, "ReadCaptureResponse"))

	done := make(chan struct{})
	go func() {
		for {
			res, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				logger.Info("clean stop, done")
				cancel(nil)
				break
			}
			code := status.Code(err)
			if code != codes.OK {
				err = fmt.Errorf("receive non-OK code: %v: %w", code, err)
				cancel(err)
				break
			}

			switch p := res.Payload.(type) {
			case *CaptureResponse_Message:
				c.messageWriter.WriteMessage(p.Message)
			case *CaptureResponse_Packet:
				writePacket(p.Packet, packetWriter)
			}
		}
		close(done)
	}()

	return done
}

// writePacket writes a Packet to the outputFile (in packetWriter).
func writePacket(packet *Packet, packetWriter *pcapgo.Writer) {
	log := zap.L()
	if log.Level().Enabled(zap.DebugLevel) {
		log.Debug("received packet", zap.Int("bytes", len(packet.Data)), zap.Time("capture-timestamp", packet.Timestamp.AsTime()))
	}

	captureInfo := gopacket.CaptureInfo{
		Timestamp:      packet.Timestamp.AsTime(),
		CaptureLength:  len(packet.Data),
		Length:         int(packet.Length),
		InterfaceIndex: 0,
		AncillaryData:  nil,
	}
	err := packetWriter.WritePacket(captureInfo, packet.Data)
	if err != nil {
		log.Error("writing packet to file failed", zap.Error(err))
	}
}

// logProgress logs out the size of the outputFile every 5 seconds (see logProgressWait).
func (c *Client) logProgress(ctx context.Context, logger *zap.Logger) {
	ticker := time.NewTicker(logProgressWait)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			info, err := c.packetFile.Stat()
			if err != nil {
				logger.Debug("could not inspect output file", zap.Error(err))
				return
			}
			logger.Debug(fmt.Sprintf("%s bytes written to disk (total).", bytefmt.ByteSize(uint64(info.Size()))))
		case <-ctx.Done():
			return
		}
	}
}

// CheckAPIHandler checks if API is healthy and the given handler is available, if that's the case, the returned error will be nil.
func (c *Client) CheckAPIHandler(handler string) error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultStatusTimeout)
	defer cancel()

	if c.cc == nil {
		return ErrNotConnected
	}

	statusResponse, err := c.Status(ctx, &StatusRequest{})
	if err != nil {
		return fmt.Errorf("could not fetch api status: %w", err)
	}

	if !statusResponse.GetHealthy() {
		return fmt.Errorf("pcap-api reported unhealthy status")
	}

	for _, resolverName := range statusResponse.Resolvers {
		if resolverName == handler {
			return nil
		}
	}
	return fmt.Errorf("pcap-api does not support handler %v", handler)
}
