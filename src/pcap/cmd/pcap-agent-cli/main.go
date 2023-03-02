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
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"github.com/cloudfoundry/pcap-release/src/pcap/cmd"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	log := zap.L()

	cc, err := grpc.Dial("localhost:8083", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal("unable to establish connection", zap.Error(err))
	}

	agentClient := pcap.NewAgentClient(cc)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	statusRes, err := agentClient.Status(ctx, &pcap.StatusRequest{})
	if err != nil {
		log.Panic("unable to get agent status", zap.Error(err))
	}
	log.Info("status:")
	log.Sugar().Infof("  healthy: %v\n", statusRes.Healthy)
	log.Sugar().Infof("  compLvl: %d\n", statusRes.CompatibilityLevel)
	log.Sugar().Infof("  message: %s\n", statusRes.Message)

	stream, err := agentClient.Capture(ctx)
	if err != nil {
		log.Panic("error during capturing", zap.Error(err))
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
		log.Panic("unable to start capture", zap.Error(err))
	}

	cmd.ReadN(10, stream) //nolint:gomnd // default value used for testing

	err = stream.Send(&pcap.AgentRequest{
		Payload: &pcap.AgentRequest_Stop{},
	})
	if err != nil {
		log.Panic("unable to stop capture", zap.Error(err))
	}

	cmd.ReadN(10_000, stream) //nolint:gomnd // default value used for testing
}
