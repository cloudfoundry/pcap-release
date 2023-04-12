// pcap-agent-cli is a simple client to manually test the pcap-agent and confirm
// it's operating as expected.
//
// NOT MEANT FOR PRODUCTION USE!
//
// It will connect to port 8083 on the loopback
// interface and request a capture from the `en0` device. The first 10 packets are
// read and each packet causes a print to the console. After ten packets have been
// read a message to stop the capture is sent and any remaining packets (but at most
// 10.000) are read.
//
// Any messages that occur while performing the test are also printed to the console
// and any errors cause the cli to exit.
package main

import (
	"context"
	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/devtools"
	"os"

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

	cc, err := grpc.Dial("localhost:8083", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Error("unable to establish connection", zap.Error(err))
		return
	}

	agentClient := pcap.NewAgentClient(cc)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, pcap.DefaultStatusTimeout)
	defer cancel()

	statusRes, err := agentClient.Status(ctx, &pcap.StatusRequest{})
	if err != nil {
		log.Error("unable to get agent status", zap.Error(err))
		return
	}
	log.Info("status:")
	log.Sugar().Infof("  healthy: %v\n", statusRes.Healthy)
	log.Sugar().Infof("  compLvl: %d\n", statusRes.CompatibilityLevel)
	log.Sugar().Infof("  message: %s\n", statusRes.Message)

	stream, err := agentClient.Capture(ctx)
	if err != nil {
		log.Error("error during capturing", zap.Error(err))
		return
	}

	err = stream.Send(&pcap.AgentRequest{
		Payload: &pcap.AgentRequest_Start{
			Start: &pcap.StartAgentCapture{
				Capture: &pcap.CaptureOptions{
					Device:  "en0",
					Filter:  "",
					SnapLen: 65000, //nolint:gomnd // default value used for testing
				},
			},
		},
	})
	if err != nil {
		log.Error("unable to start capture", zap.Error(err))
		return
	}

	devtools.ReadN(10, stream) //nolint:gomnd // default value used for testing

	err = stream.Send(&pcap.AgentRequest{
		Payload: &pcap.AgentRequest_Stop{},
	})
	if err != nil {
		log.Error("unable to stop capture", zap.Error(err))
		return
	}

	devtools.ReadN(10_000, stream) //nolint:gomnd // default value used for testing
}
