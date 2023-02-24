package pcap

import (
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
	"time"
)

type Client struct {
	endpointRequest *EndpointRequest
	captureOptions  *CaptureOptions
	packetOut       io.Writer
	messageOut      io.Writer
	signalChannel   chan os.Signal
	query           *BoshQuery
	apiClient       APIClient
	apiURL          string
	ctx             context.Context
}

func NewClient(request *EndpointRequest, captureOptions *CaptureOptions, outputFile string, apiURL string) *Client {
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
				fmt.Println(err)
			}
		} else {
			log.Errorf("output file %s already exists", outputFile)
		}
	}

	return client
}
func (client *Client) Setup() {

	cc, err := grpc.Dial(client.apiURL, grpc.WithTransportCredentials(insecure.NewCredentials())) // fixme: credentials
	if err != nil {
		panic(err.Error())
	}

	client.ctx = context.Background()
	ctx, cancel := context.WithTimeout(client.ctx, time.Minute)
	defer cancel()

	client.apiClient = NewAPIClient(cc)

	statusResponse, err := client.apiClient.Status(ctx, &StatusRequest{})

	if !statusResponse.GetHealthy() {
		err = fmt.Errorf("api not up")
		return
	}

	if client.endpointRequest.GetBosh() != nil {
		if !statusResponse.GetBosh() {
			err = fmt.Errorf("api server does not support bosh")
			return
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

	stream, err := client.apiClient.Capture(client.ctx)

	err = stream.Send(request)
	if err != nil {
		panic(err.Error())
	}

	// keep receiving some data long enough to start a manual drain
	for i := 0; i < 10000; i++ {
		readN(1000, stream)
		time.Sleep(200 * time.Millisecond)
	}

	stop := &CaptureRequest{
		Operation: &CaptureRequest_Stop{},
	}

	err = stream.Send(stop)
	if err != nil {
		panic(err.Error())
	}

	readN(10_000, stream)

	for {
		log.Infof("running high and dry")
		if <-client.signalChannel == os.Interrupt {

		}
	}

	log.Infof("Received Stop Signal from Client, aborting")
}

type genericStreamReceiver interface {
	Recv() (*CaptureResponse, error)
}

func readN(n int, stream genericStreamReceiver) {
	for i := 0; i < n; i++ {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			fmt.Println("clean stop, done")
			return
		}
		code := status.Code(err)
		if code != codes.OK {
			fmt.Printf("receive non-OK code: %s: %s\n", code.String(), err.Error())
			return
		}

		switch p := res.Payload.(type) {
		case *CaptureResponse_Message:
			fmt.Printf("received message (%d/%d): %s: %s\n", i+1, n, p.Message.Type.String(), p.Message.Message)
		case *CaptureResponse_Packet:
			fmt.Printf("received packet  (%d/%d): %d bytes\n", i+1, n, len(p.Packet.Data))
		}
	}
}

//var parameters url.Values = map[string][]string{
//	"deployment":  {opts.Deployment},
//	"device":      {opts.Interface},
//	"filter":      {opts.Filter},
//	"instance_id": opts.InstanceIds,
//	"group":       opts.InstanceGroups,
//}
//
//req := &http.Request{
//	Method: "GET",
//	URL: &url.URL{
//		Scheme:   "https",
//		Host:     opts.PcapAPIURL,
//		Path:     "/capture/bosh",
//		RawQuery: parameters.Encode(),
//	},
//	Header: map[string][]string{
//		"Authorization": {fmt.Sprintf("Bearer %s", token.access)}, // TODO: bosh requires an upper-case version of `bearer` even though it is case insensitive, but there is a access token type which is lower-case...
//	},
//}
//
//instanceIds := "all"
//if len(opts.InstanceIds) > 0 {
//	instanceIds = strings.Join(opts.InstanceIds, ", ")
//}
//
//fmt.Printf("Capturing traffic of deployment: %s groups: %v instances: %v into file %s ...\n", opts.Deployment, opts.InstanceGroups, instanceIds, opts.File)
//res, err := client.Do(req)
//if err != nil {
//	fmt.Printf("Could not receive pcap stream: %s\n", err)
//	return
//}
//fmt.Println("foo")
//
//defer silentClose(res.Body)
//
//if res.StatusCode != http.StatusOK {
//	var msg []byte
//	msg, err = io.ReadAll(res.Body)
//	if err != nil {
//		panic(err.Error())
//	}
//
//	err = fmt.Errorf("unexpected statusResponse code api: %d (%s)", res.StatusCode, string(msg))
//	return
//}
//
//file, err := os.Create(opts.File)
//if err != nil {
//	return
//}
//
//defer silentClose(file)
//
//copyWg := &sync.WaitGroup{}
//copyWg.Add(1)
//go func(writer io.Writer, reader io.Reader) {
//	written, err := io.CopyBuffer(writer, reader, make([]byte, 1048576)) // 1 Mebibyte
//	if err != nil {
//		log.Errorf("copy operation stopped: %s", err.Error())
//	}
//	log.Infof("captured %s", bytefmt.ByteSize(uint64(written)))
//	copyWg.Done()
//}(file, res.Body)
//
//stopProgress := make(chan bool)
//go progress(file, stopProgress)
//
//log.Debug("registering signal handler for SIGINT")
//sigChan := make(chan os.Signal, 1)
//signal.Notify(sigChan, os.Interrupt)
//
//log.Debug("waiting for SIGINT to be sent")
//<-sigChan
//
//log.Debug("received SIGINT, stopping progress")
//stopProgress <- true
//
//log.Debug("stopping capture by closing response body")
//err = res.Body.Close()
//
//log.Debug("waiting for copy operation to stop")
//copyWg.Wait()
//
//log.Debug("syncing file to disk")
//err = file.Sync()
//if err != nil {
//	return
//}
//
//log.Debug("closing file")
//err = file.Close()
//if err != nil {
//	return
//},,
