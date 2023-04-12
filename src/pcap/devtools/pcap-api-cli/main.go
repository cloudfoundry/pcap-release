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
	"os"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/devtools"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	log := zap.L()

	var err error

	defer func() {
		if err != nil {
			os.Exit(1)
		}
	}()

	cc, err := grpc.Dial("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal("unable to establish connection", zap.Error(err))
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	api := pcap.NewAPIClient(cc)

	statusRes, err := api.Status(ctx, &pcap.StatusRequest{})
	if err != nil {
		log.Fatal("unable to get api status", zap.Error(err))
		return
	}
	// This whole client is temporary, so leaving the sugared zap logger here.
	log.Info("status:", zap.Bool("healthy", statusRes.Healthy), zap.Int64("compatibility-level", statusRes.CompatibilityLevel), zap.String("message", statusRes.Message))

	stream, err := api.Capture(ctx)
	if err != nil {
		log.Error("error during capturing", zap.Error(err))
		return
	}

	request := &pcap.CaptureRequest{
		Operation: &pcap.CaptureRequest_Start{
			Start: &pcap.StartCapture{
				Request: &pcap.EndpointRequest{
					Request: &pcap.EndpointRequest_Bosh{
						Bosh: &pcap.BoshRequest{
							Token:      "123",
							Deployment: "cf",
							Groups:     []string{"router"},
						},
					},
				},
				Options: &pcap.CaptureOptions{
					Device:  "en0",
					Filter:  "",
					SnapLen: 65000, //nolint:gomnd // default value used for testing
				},
			},
		},
	}

	err = stream.Send(request)
	if err != nil {
		log.Error("unable to start capture", zap.Error(err))
		return
	}

	// keep receiving some data long enough to start a manual drain
	for i := 0; i < 10000; i++ {
		devtools.ReadN(1000, stream)       //nolint:gomnd // default value used for testing
		time.Sleep(200 * time.Millisecond) //nolint:gomnd // default value used for testing
	}

	err = stream.Send(pcap.MakeStopRequest())
	if err != nil {
		log.Error("unable to stop capture", zap.Error(err))
		return
	}

	devtools.ReadN(10_000, stream) //nolint:gomnd // default value used for testing
}
