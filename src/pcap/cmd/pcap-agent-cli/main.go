//nolint:all // this is just a dirty hack to test the agent stand-alone
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
	cc, err := grpc.Dial("localhost:8083", grpc.WithTransportCredentials(insecure.NewCredentials()))
	p(err)
	agentClient := pcap.NewAgentClient(cc)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	statusRes, err := agentClient.Status(ctx, &pcap.StatusRequest{})
	p(err)
	fmt.Println("status:")
	fmt.Printf("  health : %s\n", statusRes.Health.String())
	fmt.Printf("  version: %s\n", statusRes.Version)
	fmt.Printf("  status : %s\n", statusRes.Status)

	stream, err := agentClient.Capture(ctx)
	p(err)

	err = stream.Send(&pcap.AgentRequest{
		Payload: &pcap.AgentRequest_Start{
			Start: &pcap.StartAgentCapture{
				Capture: &pcap.CaptureOptions{
					Device:  "en0",
					Filter:  "",
					SnapLen: 65000,
				},
				Context: &pcap.Context{
					TraceId: "1bd89b5d-6776-4ca4-b637-3187617f1579",
				},
			},
		},
	})
	p(err)

	readN(10, stream)

	err = stream.Send(&pcap.AgentRequest{
		Payload: &pcap.AgentRequest_Stop{},
	})
	p(err)

	readN(10000, stream)
}

func readN(n int, stream pcap.Agent_CaptureClient) {
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
