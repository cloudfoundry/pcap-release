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
	"github.com/cloudfoundry/pcap-release/src/pcap/cmd"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	cc, err := grpc.Dial("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	cmd.P(err)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	// ctx = metadata.NewOutgoingContext(ctx, metadata.MD{pcap.HeaderVcapID: []string{"123"}})

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
	cmd.P(err)
	// keep receiving some data long enough to start a manual drain
	for i := 0; i < 10000; i++ {
		cmd.ReadN(1000, stream)
		time.Sleep(200 * time.Millisecond)
	}

	stop := &pcap.CaptureRequest{
		Operation: &pcap.CaptureRequest_Stop{},
	}

	err = stream.Send(stop)
	cmd.P(err)

	cmd.ReadN(10_000, stream)
}
