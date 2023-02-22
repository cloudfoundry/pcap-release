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
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/cmd"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	log := zap.L()

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
		log.Panic("unable to get api status", zap.Error(err))
	}
	// This whole client is temporary, so leaving the sugared zap logger here.
	log.Info("status:")
	log.Sugar().Infof("  healthy: %v\n", statusRes.Healthy)
	log.Sugar().Infof("  compLvl: %d\n", statusRes.CompatibilityLevel)
	log.Sugar().Infof("  message: %s\n", statusRes.Message)

	stream, err := api.Capture(ctx)
	if err != nil {
		log.Panic("error during capturing", zap.Error(err))
	}

	request := &pcap.CaptureRequest{
		Operation: &pcap.CaptureRequest_Start{
			Start: &pcap.StartCapture{
				Capture: &pcap.EndpointRequest{
					Capture: &pcap.Capture_Bosh{
						Bosh: &pcap.BoshQuery{
							Token:      "123",
							Deployment: "cf",
							Groups:     []string{"router"}},
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
		log.Panic("unable to start capture", zap.Error(err))
	}

	// keep receiving some data long enough to start a manual drain
	for i := 0; i < 10000; i++ {
		cmd.ReadN(1000, stream)            //nolint:gomnd // default value used for testing
		time.Sleep(200 * time.Millisecond) //nolint:gomnd // default value used for testing
	}

	stop := &pcap.CaptureRequest{
		Operation: &pcap.CaptureRequest_Stop{},
	}

	err = stream.Send(stop)
	if err != nil {
		log.Panic("unable to stop capture", zap.Error(err))
	}

	cmd.ReadN(10_000, stream) //nolint:gomnd // default value used for testing
}
