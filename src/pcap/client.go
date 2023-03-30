package pcap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sync"
	"time"

	"code.cloudfoundry.org/bytefmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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
	writeMessage(message *Message)
}

type ConsoleMessageWriter struct {
	Log *zap.Logger
}

// writeMessage accepts a Message and writes a log-line using a log-level corresponding to the severity of the message.
func (c ConsoleMessageWriter) writeMessage(message *Message) {
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
	aPIClient
}

func CloseQuietly(closer io.Closer) {
	_ = closer.Close()
}

// NewClient sets up logging for the client and creates the outputFile.
// It assumes that the outputFile does not pre-exist and that the path is writeable (should be checked by CLI).
//
// NewClient returns a new Client if there are no issues with outputFile creation.
func NewClient(outputFile string, logger *zap.Logger, writer MessageWriter) (*Client, error) {
	var err error

	client := &Client{log: logger, messageWriter: writer}

	if len(outputFile) == 0 {
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

func (c *Client) Wait() {

}

// ConnectToAPI sets up the grpc-connection between client and pcap-api.
//
// Depending on the http scheme in apiURL, it uses plain HTTP or TLS.
func (c *Client) ConnectToAPI(apiURL *url.URL) error {
	var (
		err   error
		creds credentials.TransportCredentials
	)

	if apiURL.Scheme == "https" {
		creds, err = LoadTLSCredentials("", "", nil, nil, nil)
		if err != nil {
			return fmt.Errorf("could not generate TLS credentials %w", err)
		}
	} else { // plain http
		creds = insecure.NewCredentials()
	}

	c.cc, err = grpc.Dial(apiURL.Host, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("could not connect to pcap-api (%v)", apiURL)
	}

	return nil
}

// TODO: (discussion) We should brainstorm more appropriate names for HandleRequest and handleStream

// HandleRequest is the wrapper function for all operations around an EndpointRequest.
// It writes the pcap-header to the outputFile, sends the CaptureRequest to the pcap-api
// and handles the cleanup after the capture is done.
// It then delegates writing individual packets and logging messages from the api to handleStream.
// logProgress is called in another goroutine to asynchronously write out the bytes written to the outputFile.
func (c *Client) HandleRequest(ctx context.Context, endpointRequest *EndpointRequest, options *CaptureOptions, cancel context.CancelCauseFunc) error {
	logger := c.log.With(zap.String(LogKeyHandler, "HandleRequest"))
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

	copyWg := &sync.WaitGroup{}
	copyWg.Add(1)
	go c.handleStream(c.stream, packetWriter, copyWg, cancel)

	go c.logProgress(ctx)

	// wait for progress to finish
	<-ctx.Done()

	logger.Info("waiting for copy operation to stop")
	copyWg.Wait()

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

func (c *Client) StopRequest() {
	err := c.stream.SendMsg(MakeStopRequest())
	if err != nil {
		c.log.Error("could not stop")
	}
}

// handleStream reads CaptureResponse's from the api in a loop and delegates writing/logging messages & packets to writeMessage / writePacket.
//
// It terminates if an error or clean stop-message is received.
func (c *Client) handleStream(stream API_CaptureClient, packetWriter *pcapgo.Writer, copyWg *sync.WaitGroup, cancel context.CancelCauseFunc) {
	logger := c.log.With(zap.String(LogKeyHandler, "handleStream"))
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
			c.messageWriter.writeMessage(p.Message)
		case *CaptureResponse_Packet:
			writePacket(p.Packet, packetWriter)
		}
	}
	copyWg.Done()
}

// writePacket writes a Packet to the outputFile (in packetWriter).
func writePacket(packet *Packet, packetWriter *pcapgo.Writer) {
	log := zap.L()
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
	if log.Level().Enabled(zap.DebugLevel) {
		log.Debug("received packet", zap.Int("bytes", len(packet.Data)), zap.Time("capture-timestamp", packet.Timestamp.AsTime()))
	}
}

// logProgress logs out the size of the outputFile every 5 seconds (see logProgressWait).
func (c *Client) logProgress(ctx context.Context) {
	logger := zap.L()
	if c.packetFile == os.Stdout {
		// writing progress information could interfere with packet output when both are written to stdout
		logger.Debug("writing captures to stdout, skipping write-progress logs")
		return
	}

	// this is an endless function, so it's ok to use time.Tick()
	ticker := time.Tick(logProgressWait) // nolint
	for {
		select {
		case <-ticker:
			info, err := c.packetFile.Stat()
			if err != nil {
				logger.Debug("pcap output file already closed: ", zap.Error(err))
				return
			}
			logger.Debug(fmt.Sprintf("%s bytes written to disk (total).", bytefmt.ByteSize(uint64(info.Size()))))
		case <-ctx.Done():
			return
		}
	}
}
