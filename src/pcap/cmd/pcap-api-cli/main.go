// pcap-api-cli is a simple client to manually test the pcap-api and confirm
// it's operating as expected.
//
// NOT MEANT FOR PRODUCTION USE!
//
// It will connect to port 8080 on the loopback
// interface and interactively guide through creating a CF or BOSH request.
//
// Any messages that occur while performing the test are also printed to the console
// and any errors cause the cli to exit.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func main() {
	cc, err := grpc.Dial("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	p(err)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	api := pcap.NewAPIClient(cc)
	stream, err := api.Capture(ctx)

	request := &pcap.CaptureRequest{
		Operation: &pcap.CaptureRequest_Start{
			Start: &pcap.StartCapture{
				Capture: &pcap.Capture{
					Capture: &pcap.Capture_Bosh{
						Bosh: &pcap.BoshCapture{
							Token:      "123",
							Deployment: "cf",
							Groups:     []string{"router"}},
					},
				},
				Options: &pcap.CaptureOptions{
					Device:  "en0",
					Filter:  "",
					SnapLen: 65000,
				},
			},
		},
	}

	err = stream.Send(request)
	p(err)

	readN(10, stream)

	stop := &pcap.CaptureRequest{
		Operation: &pcap.CaptureRequest_Stop{},
	}

	err = stream.Send(stop)
	p(err)

	readN(10_000, stream)

}

type genericStreamReceiver interface {
	Recv() (*pcap.CaptureResponse, error)
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
		case *pcap.CaptureResponse_Message:
			fmt.Printf("received message (%d/%d): %s: %s\n", i+1, n, p.Message.Type.String(), p.Message.Message)
		case *pcap.CaptureResponse_Packet:
			fmt.Printf("received packet  (%d/%d): %d bytes\n", i+1, n, len(p.Packet.Data))
		}
	}
}

func p(err error) {
	if err != nil {
		panic(err.Error())
	}
}
