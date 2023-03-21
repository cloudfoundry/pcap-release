package dev_tools

import (
	"errors"
	"io"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cloudfoundry/pcap-release/src/pcap"
)

type genericStreamReceiver interface {
	Recv() (*pcap.CaptureResponse, error)
}

// ReadN reads a number of messages from stream
// TODO: Remove this when we have a proper CLI
func ReadN(n int, stream genericStreamReceiver) {
	for i := 0; i < n; i++ {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			zap.S().Infof("clean stop, done")
			return
		}
		code := status.Code(err)
		if code != codes.OK {
			zap.S().Infof("receive non-OK code: %s: %s\n", code.String(), err.Error())
			return
		}

		switch p := res.Payload.(type) {
		case *pcap.CaptureResponse_Message:
			zap.S().Infof("received message (%d/%d): %s: %s\n", i+1, n, p.Message.Type.String(), p.Message.Message)
		case *pcap.CaptureResponse_Packet:
			zap.S().Infof("received packet  (%d/%d): %d bytes\n", i+1, n, len(p.Packet.Data))
		}
	}
}
