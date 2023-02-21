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

//nolint:all // this is just a dirty hack to test the agent stand-alone

import (
	"context"
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap/cmd"
	"time"

	"github.com/cloudfoundry/pcap-release/src/pcap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	cc, err := grpc.Dial("localhost:8083", grpc.WithTransportCredentials(insecure.NewCredentials()))
	cmd.P(err)
	agentClient := pcap.NewAgentClient(cc)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	statusRes, err := agentClient.Status(ctx, &pcap.StatusRequest{})
	cmd.P(err)
	fmt.Println("status:")
	fmt.Printf("  healthy: %v\n", statusRes.Healthy)
	fmt.Printf("  compLvl: %d\n", statusRes.CompatibilityLevel)
	fmt.Printf("  message: %s\n", statusRes.Message)

	stream, err := agentClient.Capture(ctx)
	cmd.P(err)

	err = stream.Send(&pcap.AgentRequest{
		Payload: &pcap.AgentRequest_Start{
			Start: &pcap.StartAgentCapture{
				Capture: &pcap.CaptureOptions{
					Device:  "en0",
					Filter:  "",
					SnapLen: 65000,
				},
			},
		},
	})
	cmd.P(err)

	cmd.ReadN(10, stream)

	err = stream.Send(&pcap.AgentRequest{
		Payload: &pcap.AgentRequest_Stop{},
	})
	cmd.P(err)

	cmd.ReadN(10_000, stream)
}
