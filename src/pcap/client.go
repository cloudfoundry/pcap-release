package pcap

import (
	"code.cloudfoundry.org/bytefmt"
	"context"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"io"
	"os"
	"os/signal"
	"sync"
	"time"
)

type Client struct {
	endpointRequest *EndpointRequest
	captureOptions  *CaptureOptions
	packetOut       *os.File
	messageOut      *os.File
	signalChannel   chan os.Signal
	query           *BoshQuery
	apiClient       APIClient
	apiURL          string
	ctx             context.Context
}

func NewClient(request *EndpointRequest, captureOptions *CaptureOptions, outputFile string, apiURL string) (*Client, error) {
	client := &Client{
		endpointRequest: request,
		messageOut:      os.Stderr,
		signalChannel:   make(chan os.Signal, 1),
		apiURL:          apiURL,
		captureOptions:  captureOptions,
	}

	if len(outputFile) == 0 {
		client.packetOut = os.Stdout
	} else {
		if _, err := os.Stat(outputFile); os.IsNotExist(err) {
			client.packetOut, err = os.Create(outputFile)
			if err != nil {
				return nil, fmt.Errorf("could not create file %v: %v ", outputFile, err.Error())
			}
		} else {
			return nil, fmt.Errorf("output file %s already exists", outputFile)
		}
	}

	client.connectToAPI()

	return client, nil
}
func (client *Client) connectToAPI() {

	cc, err := grpc.Dial(client.apiURL, grpc.WithTransportCredentials(insecure.NewCredentials())) // fixme: credentials
	if err != nil {
		log.Fatalf("Could not connect to pcap-api (%v)", client.apiURL)
	}

	client.ctx = context.Background()
	ctx, cancel := context.WithTimeout(client.ctx, time.Minute)
	defer cancel()

	client.apiClient = NewAPIClient(cc)

	statusResponse, err := client.apiClient.Status(ctx, &StatusRequest{})

	if !statusResponse.GetHealthy() {
		log.Fatalf("api not up")
	}

	if client.endpointRequest.GetBosh() != nil {
		if !statusResponse.GetBosh() {
			log.Fatalf("api server does not support bosh")
		}
	} else if client.endpointRequest.GetCf() != nil {
		//TODO
		panic("not yet implemented")
	} else {
		log.Fatalf("unknown endpoint request type")
	}
}

func (client *Client) HandleRequest() {

	request := &CaptureRequest{
		Operation: &CaptureRequest_Start{
			Start: &StartCapture{
				Capture: client.endpointRequest,
				Options: client.captureOptions,
			},
		},
	}

	stream, err := client.apiClient.Capture(client.ctx) //TODO: errorhandling

	err = stream.Send(request)
	if err != nil {
		panic(err.Error())
	}

	defer silentClose(client.packetOut) // TODO: still necessary?

	copyWg := &sync.WaitGroup{}
	copyWg.Add(1)
	go func(writer io.Writer, stream API_CaptureClient) {
		counter := 0

		for {
			counter++
			time.Sleep(200 * time.Millisecond) //TODO: make configurable?

			res, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				fmt.Println("clean stop, done")
				break
			}
			code := status.Code(err)
			if code != codes.OK {
				fmt.Printf("receive non-OK code: %s: %s\n", code.String(), err.Error())
				break
			}

			switch p := res.Payload.(type) {
			case *CaptureResponse_Message:
				fmt.Printf("received message (#%d): %s: %s\n", counter, p.Message.Type.String(), p.Message.Message)
				switch p.Message.Type {
				case MessageType_CAPTURE_STOPPED:
					log.Infof("Received capture stop signal")
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
				fmt.Printf("received packet  (#%d): %d bytes\n", counter, len(p.Packet.Data))
				written, err := client.packetOut.Write(p.Packet.Data)
				if err != nil {
					log.Errorf("copy operation stopped: %s", err.Error())
				}
				log.Infof("captured %s", bytefmt.ByteSize(uint64(written)))
			}
		}

		client.signalChannel <- os.Interrupt //fixme: working but dirty solution to stop cli after the capture was stopped by api or agent
		copyWg.Done()
	}(client.packetOut, stream)

	stopProgress := make(chan bool)
	go progress(client.packetOut, stopProgress)

	log.Debug("registering signal handler for SIGINT")
	client.signalChannel = make(chan os.Signal, 1)
	signal.Notify(client.signalChannel, os.Interrupt)

	log.Debug("waiting for SIGINT to be sent")
	<-client.signalChannel //TODO: what if capture fails before we get here
	//TODO: timed captures?

	log.Debug("received SIGINT, stopping progress")
	stopProgress <- true

	log.Debug("stopping capture by sending stop request")
	stop := &CaptureRequest{
		Operation: &CaptureRequest_Stop{},
	}
	err = stream.Send(stop)

	log.Debug("waiting for copy operation to stop")
	copyWg.Wait()

	log.Debug("syncing file to disk")
	err = client.packetOut.Sync()
	if err != nil {
		return
	}

	log.Debug("closing file")
	err = client.packetOut.Close()
	if err != nil {
		return
	}

	if err != nil {
		panic(err.Error())
	}
}

func progress(file *os.File, stop <-chan bool) {
	ticker := time.Tick(time.Second)
	for {
		select {
		case <-ticker:
			info, err := file.Stat()
			if err != nil {
				panic(err.Error())
			}

			fmt.Printf("\033[2K\rWrote %s bytes to disk.", bytefmt.ByteSize(uint64(info.Size())))
		case <-stop:
			return
		}
	}
}

// silentClose ignores errors returned when closing the io.Closer.
func silentClose(closer io.Closer) {
	_ = closer.Close()
}
