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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"io"
	"os"
	"sync"
	"time"
)

type Client struct {
	endpointRequest *EndpointRequest
	captureOptions  *CaptureOptions
	packetFile      *os.File
	packetWriter    *pcapgo.Writer
	messageOut      *os.File
	apiURL          string
	ctx             context.Context
	stopChannel     chan StopSignal
	aPIClient
}

type StopSignal int32

const (
	Stop_client StopSignal = 1
	Stop_api    StopSignal = 2
)

func NewClient(request *EndpointRequest, captureOptions *CaptureOptions, outputFile string, apiURL string, stopChannel chan StopSignal) (*Client, error) {
	var err error
	client := &Client{
		endpointRequest: request,
		captureOptions:  captureOptions,
		messageOut:      os.Stderr,
		stopChannel:     stopChannel,
		apiURL:          apiURL,
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
	client.packetWriter = pcapgo.NewWriter(client.packetFile)
	err = client.packetWriter.WriteFileHeader(captureOptions.SnapLen, layers.LinkTypeEthernet)
	if err != nil {
		return nil, err
	}

	err = client.connectToAPI()
	if err != nil {
		return nil, err
	}

	return client, nil
}
func (client *Client) connectToAPI() error {
	var err error
	client.cc, err = grpc.Dial(client.apiURL, grpc.WithTransportCredentials(insecure.NewCredentials())) // fixme: credentials
	if err != nil {
		return fmt.Errorf("Could not connect to pcap-api (%v)", client.apiURL)
	}

	client.ctx = context.Background()
	ctx, cancel := context.WithTimeout(client.ctx, time.Minute)
	defer cancel()

	statusResponse, err := client.Status(ctx, &StatusRequest{})
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	if !statusResponse.GetHealthy() {
		return fmt.Errorf("api not up") // TODO
	}

	switch {
	case client.endpointRequest.GetBosh() != nil:
		if !statusResponse.GetBosh() {
			return fmt.Errorf("api server does not support bosh")
		}
	case client.endpointRequest.GetCf() != nil:
		panic("not yet implemented")
	default:
		return fmt.Errorf("unknown endpoint request type")
	}
	return nil
}

func (client *Client) HandleRequest() error {
	request := &CaptureRequest{
		Operation: &CaptureRequest_Start{
			Start: &StartCapture{
				Capture: client.endpointRequest,
				Options: client.captureOptions,
			},
		},
	}

	var stream, err = client.Capture(client.ctx)
	if err != nil {
		return err
	}

	err = stream.Send(request)
	if err != nil {
		return err
	}

	copyWg := &sync.WaitGroup{}
	copyWg.Add(1)
	go client.handleStream(stream, copyWg)

	go client.logProgress(client.stopChannel)

	// wait for progress to finish
	stopSignal := <-client.stopChannel

	if stopSignal == Stop_client {
		log.Debug("stopping capture by sending stop request")
		stop := &CaptureRequest{
			Operation: &CaptureRequest_Stop{},
		}
		err = stream.Send(stop)
		if err != nil {
			return err
		}
	}

	log.Debug("waiting for copy operation to stop")
	copyWg.Wait()

	log.Debug("syncing file to disk")
	err = client.packetFile.Sync()
	if err != nil {
		return err
	}

	log.Debug("closing file")
	err = client.packetFile.Close()
	if err != nil {
		return err
	}

	return nil
}

func (client *Client) handleStream(stream API_CaptureClient, copyWg *sync.WaitGroup) {
	counter := 0

	for {
		counter++
		time.Sleep(200 * time.Millisecond) //TODO: make configurable?

		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			fmt.Println("clean stop, done")
			client.stopChannel <- Stop_api
			break
		}
		code := status.Code(err)
		if code != codes.OK {
			fmt.Printf("receive non-OK code: %s: %s\n", code.String(), err.Error())
			client.stopChannel <- Stop_api
			break
		}

		switch p := res.Payload.(type) {
		case *CaptureResponse_Message:
			fmt.Printf("received message (#%d): %s: %s\n", counter, p.Message.Type.String(), p.Message.Message)
			switch p.Message.Type {
			case MessageType_CAPTURE_STOPPED:
				log.Infof("Received capture stop signal")
				client.stopChannel <- Stop_api
				break
			case MessageType_START_CAPTURE_FAILED:
				log.Infof("Received MessageType_START_CAPTURE_FAILED signal") //TODO
				break
			case MessageType_INSTANCE_UNAVAILABLE:
				log.Infof("Received MessageType_INSTANCE_UNAVAILABLE signal") //TODO
				break
				//TODO: Other MessageTypes?
			}
		case *CaptureResponse_Packet:
			packetLength := len(p.Packet.Data)
			fmt.Printf("received packet  (#%d): %d bytes\n", counter, packetLength)

			packet := gopacket.NewPacket(p.Packet.Data, layers.LinkTypeEthernet, gopacket.Default)
			if packet.ErrorLayer() != nil && packet.ErrorLayer().Error() != nil {
				panic(packet.ErrorLayer().Error().Error()) //TODO: logging
			}
			//TODO: workaround, see CFN-2950
			captureInfo := gopacket.CaptureInfo{
				Timestamp:      time.Now(),
				CaptureLength:  packetLength,
				Length:         packetLength,
				InterfaceIndex: 0,
				AncillaryData:  nil,
			}
			err = client.packetWriter.WritePacket(captureInfo, packet.Data())
			if err != nil {
				log.Errorf("copy operation stopped: %s", err.Error())
			}
		}
	}
	copyWg.Done()
}

func (client *Client) logProgress(stop <-chan StopSignal) {
	if client.packetFile == os.Stdout {
		//writing progress information could interfere with packet output when both are written to stdout
		return
	}

	ticker := time.Tick(time.Second)
	for {
		select {
		case <-ticker:
			info, err := client.packetFile.Stat()
			if err != nil {
				log.Debug("pcap output file already closed: ", err.Error())
				return
			}
			fmt.Printf("\033[2K\rWrote %s bytes to disk.", bytefmt.ByteSize(uint64(info.Size())))
		case <-stop:
			return
		}
	}
}
