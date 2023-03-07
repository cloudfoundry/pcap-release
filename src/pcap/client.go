package pcap

import (
	"code.cloudfoundry.org/bytefmt"
	"context"
	"errors"
	"fmt"
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
	"io"
	"net/url"
	"os"
	"sync"
	"time"
)

type Client struct {
	packetFile *os.File
	//packetWriter *pcapgo.Writer
	//messageOut   *os.File  // TODO: may be required later to set message output target
	ctx            context.Context
	stopChannel    chan StopSignal
	logger         *zap.Logger // TODO: really necessary?
	tlsCredentials credentials.TransportCredentials
	aPIClient
}

type StopSignal int32

const (
	Stop_client StopSignal = 1
	Stop_api    StopSignal = 2
)

func NewClient(outputFile string, apiURL string, stopChannel chan StopSignal, logger *zap.Logger) (*Client, error) {
	var err error

	client := &Client{
		//messageOut:  os.Stderr,
		stopChannel: stopChannel,
		logger:      logger,
	}

	if len(outputFile) == 0 {
		client.packetFile = os.Stdout
	} else {
		if _, err := os.Stat(outputFile); os.IsNotExist(err) {
			client.packetFile, err = os.Create(outputFile)
			if err != nil {
				return nil, fmt.Errorf("could not create file %v: %v ", outputFile, err.Error())
			}
		} else {
			return nil, fmt.Errorf("output file %s already exists", outputFile)
		}
	}

	err = client.connectToAPI(apiURL)
	if err != nil {
		return nil, err
	}

	return client, nil
}
func (client *Client) connectToAPI(apiURLstring string) error {
	var (
		err    error
		creds  credentials.TransportCredentials
		apiURL *url.URL
	)

	apiURL, err = url.Parse(apiURLstring)
	if err != nil {
		return fmt.Errorf("could not parse api-url: %v", apiURLstring)
	}
	if apiURL.Scheme == "https" {
		creds, err = LoadTLSCredentials("", "", nil, nil, nil)
		if err != nil {
			return fmt.Errorf("could not generate TLS credentials %w", err)
		}
	} else { // plain http
		creds = insecure.NewCredentials()
	}

	client.cc, err = grpc.Dial(apiURL.Host, grpc.WithTransportCredentials(creds)) // fixme: credentials
	if err != nil {
		return fmt.Errorf("could not connect to pcap-api (%v)", apiURL)
	}

	client.ctx = context.Background()
	ctx, cancel := context.WithTimeout(client.ctx, time.Minute)
	defer cancel()

	statusResponse, err := client.Status(ctx, &StatusRequest{})
	if err != nil {
		return fmt.Errorf("could not fetch api status: %v", err.Error())
	}

	if !statusResponse.GetHealthy() {
		return fmt.Errorf("api not up") // TODO
	}
	// TODO: check errorhandling if endpointRequestType (bosh/cf) is not supported by api

	return nil
}

func (client *Client) HandleRequest(endpointRequest *EndpointRequest, options *CaptureOptions) error {

	packetWriter := pcapgo.NewWriter(client.packetFile)
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
	stream, err = client.Capture(client.ctx)
	if err != nil {
		return err
	}

	err = stream.Send(captureRequest)
	if err != nil {
		return err
	}

	copyWg := &sync.WaitGroup{}
	copyWg.Add(1)
	go client.handleStream(stream, packetWriter, copyWg)

	go client.logProgress(client.stopChannel)

	// wait for progress to finish
	stopSignal := <-client.stopChannel

	if stopSignal == Stop_client {
		client.logger.Debug("stopping capture by sending stop request")
		stop := &CaptureRequest{
			Operation: &CaptureRequest_Stop{},
		}
		err = stream.Send(stop)
		if err != nil {
			return err
		}
	}

	client.logger.Debug("waiting for copy operation to stop")
	copyWg.Wait()

	client.logger.Debug("syncing file to disk")
	err = client.packetFile.Sync()
	if err != nil {
		return err
	}

	client.logger.Debug("closing file")
	err = client.packetFile.Close()
	if err != nil {
		return err
	}

	return nil
}

func (client *Client) handleStream(stream API_CaptureClient, packetWriter *pcapgo.Writer, copyWg *sync.WaitGroup) {
	for {
		time.Sleep(200 * time.Millisecond) //TODO: make configurable?

		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			client.logger.Info("clean stop, done")
			client.stopChannel <- Stop_api
			break
		}
		code := status.Code(err)
		if code != codes.OK {
			client.logger.Error("receive non-OK code: %s: %s\n", zap.Any("code", code), zap.Error(err))
			client.stopChannel <- Stop_api
			break
		}

		switch p := res.Payload.(type) {
		case *CaptureResponse_Message:
			client.writeMessage(p.Message)
		case *CaptureResponse_Packet:
			client.writePacket(p.Packet, packetWriter)
		}
	}
	copyWg.Done()
}

func (client *Client) writeMessage(message *Message) {
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
	client.logger.Log(logLevel, "received message", zap.String("message-type", message.Type.String()), zap.Any("message", message.Message))
}

func (client *Client) writePacket(packet *Packet, packetWriter *pcapgo.Writer) {
	captureInfo := gopacket.CaptureInfo{
		Timestamp:      packet.Timestamp.AsTime(),
		CaptureLength:  len(packet.Data),
		Length:         int(packet.Length),
		InterfaceIndex: 0,
		AncillaryData:  nil,
	}
	err := packetWriter.WritePacket(captureInfo, packet.Data)
	if err != nil {
		client.logger.Error("writing packet to file failed", zap.Error(err))
	}
	client.logger.Info("received packet", zap.Int("bytes", len(packet.Data)), zap.Time("capture-timestamp", packet.Timestamp.AsTime()))
}

// TODO: still needed?
func (client *Client) logProgress(stop <-chan StopSignal) {
	if client.packetFile == os.Stdout {
		//writing progress information could interfere with packet output when both are written to stdout
		client.logger.Debug("writing captures to stdout, skipping write-progress logs")
		return
	}

	ticker := time.Tick(time.Second)
	for {
		select {
		case <-ticker:
			info, err := client.packetFile.Stat()
			if err != nil {
				client.logger.Debug("pcap output file already closed: ", zap.Error(err))
				return
			}
			client.logger.Info(fmt.Sprintf("\033[2K\rWrote %s bytes to disk.", bytefmt.ByteSize(uint64(info.Size()))))
		case <-stop:
			return
		}
	}
}
