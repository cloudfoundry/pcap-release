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

type Client struct {
	packetFile *os.File
	stream     API_CaptureClient
	aPIClient
}

func NewClient(outputFile string, logger *zap.Logger) (*Client, error) {
	var err error

	client := &Client{}

	logger = logger.With(zap.String(LogKeyTarget, "client"))
	zap.ReplaceGlobals(logger)

	if len(outputFile) == 0 {
		client.packetFile = os.Stdout
	} else {
		client.packetFile, err = tryCreateOutputFile(outputFile)
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

func (c *Client) HandleRequest(ctx context.Context, endpointRequest *EndpointRequest, options *CaptureOptions, cancel CancelCauseFunc) error {
	logger := zap.L().With(zap.String(LogKeyHandler, "HandleRequest"))
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
	go handleStream(c.stream, packetWriter, copyWg, cancel)

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
	err := c.stream.SendMsg(makeStopRequest())
	if err != nil {
		zap.L().Panic("could not stop")
	}
}

func handleStream(stream API_CaptureClient, packetWriter *pcapgo.Writer, copyWg *sync.WaitGroup, cancel CancelCauseFunc) {
	logger := zap.L().With(zap.String(LogKeyHandler, "handleStream"))
	for {
		// time.Sleep(handleStreamWait)

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
			writeMessage(p.Message)
		case *CaptureResponse_Packet:
			writePacket(p.Packet, packetWriter)
		}
	}
	copyWg.Done()
}

func writeMessage(message *Message) {
	var logLevel zapcore.Level

	switch message.Type {
	case MessageType_UNKNOWN:
		logLevel = zapcore.WarnLevel
	case MessageType_INSTANCE_UNAVAILABLE:
		logLevel = zapcore.WarnLevel
	case MessageType_START_CAPTURE_FAILED:
		logLevel = zapcore.WarnLevel
	case MessageType_INVALID_REQUEST:
		logLevel = zapcore.ErrorLevel
	case MessageType_CONGESTED:
		logLevel = zapcore.WarnLevel
	case MessageType_LIMIT_REACHED:
		logLevel = zapcore.WarnLevel
	case MessageType_CAPTURE_STOPPED:
		logLevel = zapcore.InfoLevel
	case MessageType_CONNECTION_ERROR:
		logLevel = zapcore.ErrorLevel
	}
	// TODO: Find a way to assign the proper log level.
	_ = logLevel
	zap.S().Infof("%s(%s): %s", message.Origin, message.Type, message.Message)
}

func writePacket(packet *Packet, packetWriter *pcapgo.Writer) {
	captureInfo := gopacket.CaptureInfo{
		Timestamp:      packet.Timestamp.AsTime(),
		CaptureLength:  len(packet.Data),
		Length:         int(packet.Length),
		InterfaceIndex: 0,
		AncillaryData:  nil,
	}
	err := packetWriter.WritePacket(captureInfo, packet.Data)
	if err != nil {
		zap.L().Error("writing packet to file failed", zap.Error(err))
	}
	if zap.L().Level() <= zap.DebugLevel {
		zap.L().Debug("received packet", zap.Int("bytes", len(packet.Data)), zap.Time("capture-timestamp", packet.Timestamp.AsTime()))
	}
}

func (c *Client) logProgress(ctx context.Context) {
	logger := zap.L()
	if c.packetFile == os.Stdout {
		// writing progress information could interfere with packet output when both are written to stdout
		logger.Debug("writing captures to stdout, skipping write-progress logs")
		return
	}

	ticker := time.Tick(logProgressWait)
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

func tryCreateOutputFile(outputFile string) (*os.File, error) {
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		return os.Create(outputFile)
	}
	return nil, fmt.Errorf("output file %s already exists", outputFile)
}
