package pcap

import (
	"code.cloudfoundry.org/bytefmt"
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"io"
	"net/url"
	"os"
	"sync"
	"time"
)

const POLL_DELAY = 200 * time.Millisecond

type Client struct {
	packetFile *os.File
	//messageOut   *os.File  // TODO: may be required later to set message output target
	tlsCredentials credentials.TransportCredentials
	aPIClient
}

func NewClient(outputFile string, logger *zap.Logger) (*Client, error) { // TODO: remove unused logger
	var err error

	client := &Client{}

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

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	statusResponse, err := c.Status(ctx, &StatusRequest{})
	if err != nil {
		return fmt.Errorf("could not fetch api status: %v", err.Error())
	}

	if !statusResponse.GetHealthy() {
		return fmt.Errorf("api not up") // TODO
	}
	// TODO: check errorhandling if endpointRequestType (bosh/cf) is not supported by api

	return nil
}

func (c *Client) HandleRequest(endpointRequest *EndpointRequest, options *CaptureOptions, ctx context.Context, cancel CancelCauseFunc) error {
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

	var stream API_CaptureClient
	stream, err = c.Capture(ctx)
	if err != nil {
		return err
	}

	err = stream.Send(captureRequest)
	if err != nil {
		return err
	}

	copyWg := &sync.WaitGroup{}
	copyWg.Add(1)
	go handleStream(stream, packetWriter, copyWg, cancel)

	go c.logProgress(ctx)

	// wait for progress to finish
	<-ctx.Done()

	log.Debug("waiting for copy operation to stop")
	copyWg.Wait()

	log.Debug("syncing file to disk")
	err = c.packetFile.Sync()
	if err != nil {
		return err
	}

	log.Debug("closing file")
	err = c.packetFile.Close()
	if err != nil {
		return err
	}

	return nil
}

func handleStream(stream API_CaptureClient, packetWriter *pcapgo.Writer, copyWg *sync.WaitGroup, cancel CancelCauseFunc) {
	for {
		time.Sleep(POLL_DELAY)

		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			zap.L().Info("clean stop, done") // TODO: fix logger
			cancel(nil)
			break
		}
		code := status.Code(err)
		if code != codes.OK {
			err = fmt.Errorf("receive non-OK code: %v: %v\n", zap.Any("code", code), zap.Error(err))
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
	log.Infof("%s - %v", message.String(), logLevel.String()) // TODO: duplicate logging
	zap.L().Log(logLevel, "received message", zap.String("message-type", message.Type.String()), zap.Any("message", message.Message))
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
	zap.L().Info("received packet", zap.Int("bytes", len(packet.Data)), zap.Time("capture-timestamp", packet.Timestamp.AsTime()))
}

// TODO: still needed?
func (c *Client) logProgress(ctx context.Context) {
	if c.packetFile == os.Stdout {
		//writing progress information could interfere with packet output when both are written to stdout
		log.Debug("writing captures to stdout, skipping write-progress logs")
		return
	}

	ticker := time.Tick(5 * time.Second)
	for {
		select {
		case <-ticker:
			info, err := c.packetFile.Stat()
			if err != nil {
				log.Debug("pcap output file already closed: ", zap.Error(err))
				return
			}
			log.Info(fmt.Sprintf("\033[2K\rWrote %s bytes to disk.", bytefmt.ByteSize(uint64(info.Size()))))
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
