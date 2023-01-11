package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"io"
	"time"
)

func main() {
	captureTypeFlag := flag.String("capture", "bosh", "Specify the capture type bosh or cf")
	flag.Parse()
	cc, err := grpc.Dial("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	p(err)

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	api := pcap.NewAPIClient(cc)
	if *captureTypeFlag == "cf" {
		stream, err := api.CaptureCloudfoundry(ctx)
		err = stream.Send(&pcap.CloudfoundryRequest{Payload: &pcap.CloudfoundryRequest_Start{
			Start: &pcap.StartCloudfoundryCapture{
				Token: "123",
				AppId: "abc123",
				Capture: &pcap.CaptureOptions{
					Device:  "en0",
					Filter:  "",
					SnapLen: 65000,
				},
			}}})
		p(err)

		readCf(10, stream)

		err = stream.Send(&pcap.CloudfoundryRequest{
			Payload: &pcap.CloudfoundryRequest_Stop{},
		})
		p(err)

		readCf(10_000, stream)

	} else {
		stream, err := api.CaptureBosh(ctx)
		err = stream.Send(&pcap.BoshRequest{Payload: &pcap.BoshRequest_Start{
			Start: &pcap.StartBoshCapture{
				Token:      "123",
				Deployment: "cf",
				Groups:     []string{"router"},
				Capture: &pcap.CaptureOptions{
					Device:  "en0",
					Filter:  "",
					SnapLen: 65000,
				},
			}}})
		p(err)

		readBosh(10, stream)

		err = stream.Send(&pcap.BoshRequest{
			Payload: &pcap.BoshRequest_Stop{},
		})
		p(err)

		readBosh(10_000, stream)

	}
}
func readBosh(n int, stream pcap.API_CaptureBoshClient) {
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
func readCf(n int, stream pcap.API_CaptureCloudfoundryClient) {
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
