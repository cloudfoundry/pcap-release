package cmd

import (
	"errors"
	"fmt"
	"github.com/cloudfoundry/pcap-release/src/pcap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
)

type genericStreamReceiver interface {
	Recv() (*pcap.CaptureResponse, error)
}

func ReadN(n int, stream genericStreamReceiver) {
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

func P(err error) {
	if err != nil {
		panic(err.Error())
	}
}
