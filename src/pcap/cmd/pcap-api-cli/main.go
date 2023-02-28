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
	"fmt"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/cmd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	cc, err := grpc.Dial("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Errorf("unable to establish connection: %v", err)
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	api := pcap.NewAPIClient(cc)
	stream, err := api.Capture(ctx)
	if err != nil {
		fmt.Errorf("error during capturing: %v", err)
	}

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
	if err != nil {
		fmt.Errorf("unable to start capture: %v", err)
	}

	// keep receiving some data long enough to start a manual drain
	for i := 0; i < 10000; i++ {
		cmd.ReadN(1000, stream)
		time.Sleep(200 * time.Millisecond)
	}

	stop := &pcap.CaptureRequest{
		Operation: &pcap.CaptureRequest_Stop{},
	}

	err = stream.Send(stop)
	if err != nil {
		fmt.Errorf("unable to stop capture: %v", err)
	}

	cmd.ReadN(10_000, stream)
}
