// Package pcap provides types and interfaces to build a remote packet capturing
// tool. For details about the different applications see the different packages
// in `cmd/`.
package pcap

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pcap.proto

const (
	// CompatibilityLevel indicates whether two parties are compatible. Once there is a change
	// that requires both parties to be updated this value MUST be incremented by one. The calling
	// party has to ensure that the compatibility level of the called party is equal or larger and
	// refuse operation if it isn't.
	CompatibilityLevel int64 = 1

	// LogKeyVcapID sets on which field the vcap request id will be logged.
	LogKeyVcapID = "vcap-id"
	// LogKeyHandler sets the handler.
	LogKeyHandler = "handler" // TODO: improve documentation of how this should be used

	LogKeyTarget        = "target"
	LogKeyResolver      = "resolver" // TODO: currently not used.
	HeaderVcapID        = contextKeyVcapID("x-vcap-request-id")
	maxDeviceNameLength = 16
	maxFilterLength     = 5000
)

type contextKeyVcapID string

func (c contextKeyVcapID) String() string {
	return string(c)
}

// purge reads all messages from the given channel and discards them. The
// discarded messages are logged on the trace level.
func purge[T any](c <-chan T) {
	for m := range c {
		zap.L().Warn("draining channel: discarding message", zap.Any("message", m))
	}
}

// newMessageResponse wraps the message of type messageType into a CaptureResponse, which can be sent to the recipient.
func newMessageResponse(messageType MessageType, message string, origin string) *CaptureResponse {
	return &CaptureResponse{
		Payload: &CaptureResponse_Message{
			Message: &Message{
				Type:    messageType,
				Message: message,
				Origin:  origin,
			},
		},
	}
}

// newPacketResponse wraps data into a CaptureResponse, which can be sent to the recipient.
func newPacketResponse(data []byte, captureInfo gopacket.CaptureInfo) *CaptureResponse {
	return &CaptureResponse{
		Payload: &CaptureResponse_Packet{
			Packet: &Packet{
				Data:      data,
				Timestamp: timestamppb.New(captureInfo.Timestamp),
				Length:    int32(captureInfo.Length),
			},
		},
	}
}

func (opts *CaptureOptions) validate() error {
	if opts.Device == "" {
		return fmt.Errorf("expected device to be not empty string")
	}

	err := validateDevice(opts.Device)
	if err != nil {
		return err
	}

	if len(opts.Filter) > maxFilterLength {
		return fmt.Errorf("expected filter to be at most %d characters, received %d", maxFilterLength, len(opts.Filter))
	}

	if opts.SnapLen == 0 {
		return fmt.Errorf("expected snaplen to be not zero")
	}
	return nil
}

// setVcapID expands log to include the vcap-id extracted from ctx, if available.
// When no vcap-id is defined in ctx, a new random GUID is generated and add to context key HeaderVcapID and the logger.
func setVcapID(ctx context.Context, log *zap.Logger, externalVcapID *string) (context.Context, *zap.Logger) {
	vcapID, err := vcapIDFromIncomingCtx(ctx)

	if err != nil {
		if errors.Is(err, errNoVcapID) {
			log.Warn("request does not contain request id, generating one")
		}

		if externalVcapID != nil {
			vcapID = externalVcapID
		} else {
			// No existing vcap-id found, creating a new one and adding it to the context.
			newVcapID := uuid.Must(uuid.NewRandom()).String()
			vcapID = &newVcapID
		}
	}
	ctx = context.WithValue(ctx, HeaderVcapID, *vcapID)

	log = log.With(zap.String(LogKeyVcapID, *vcapID))

	return ctx, log
}

// vcapIDFromIncomingCtx finds the vcap-id from the context metadata, if available.
//
// returns errNoVcapID if no vcap-id was found in the metadata.
func vcapIDFromIncomingCtx(ctx context.Context) (*string, error) {
	var vcap *string
	var err error
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		vcap, err = getVcapFromMD(md)
		if err == nil {
			return vcap, nil
		}
	}
	return nil, errNoVcapID
}

func getVcapFromMD(md metadata.MD) (*string, error) {
	vcapReqIDs := md.Get(HeaderVcapID.String())

	if len(vcapReqIDs) > 0 {
		vcapID := vcapReqIDs[0]
		return &vcapID, nil
	}
	return nil, errNoVcapID
}

// makeStopRequest creates the generic stop CaptureRequest that can be sent to api and agent.
func makeStopRequest() *CaptureRequest {
	return &CaptureRequest{Operation: &CaptureRequest_Stop{Stop: &StopCapture{}}}
}

// forwardToStream reads Packets from src until it's closed and writes them to stream.
// If it encounters an error while doing so the error is set to cause and the cancel function
// is called. Any data left in src is discarded after a write-error occurred.
func forwardToStream(cancel CancelCauseFunc, src <-chan *CaptureResponse, stream responseSender, bufConf BufferConf, wg *sync.WaitGroup, id string) {
	go func() {
		// After this function returns we want to make sure that this channel is
		// drained properly if there is anything left in it. This avoids responses
		// left after the connection to the client broke and no more responses are
		// read from the channel.
		defer purge(src)
		defer wg.Done()

		discarding := false
		for res := range src {
			// we never discard messages, only data
			_, isMsg := res.Payload.(*CaptureResponse_Message)

			// example (values are probably a bad choice):
			// buffer size: 10
			// lower limit: 2
			// upper limit: 8
			// len(src)      => fill level of buffer
			// discarding    => are we currently discarding packet responses?
			// messages sent => how many messages have been sent up until now
			// len(src) | discarding | messages sent
			// 2        | false      | 0
			// 1        | false      | 1
			// 7        | false      | 2
			// 6        | false      | 3
			// 9        | true       | 4 // last packet was DISCARDING_MESSAGES
			// 8        | true       | 4
			// 7        | true       | 4
			// ...
			// 3        | true       | 4
			// 2        | false      | 5
			// 1        | false      | 6

			switch {
			case len(src) <= bufConf.LowerLimit: // if buffer size is zero this case will always match
				discarding = false
			case discarding && !isMsg:
				continue
			case len(src) >= bufConf.UpperLimit && !isMsg:
				discarding = true
				// this only is sent when we start discarding (and discards the current data packet)
				res = newMessageResponse(MessageType_CONGESTED, "too much back pressure, discarding packets", id)
			}

			err := stream.Send(res)
			if err != nil {
				cancel(errorf(codes.Unknown, "send response: %w", err))
				return
			}
		}
		cancel(errorf(codes.Aborted, "no data is left to forward"))
	}()
}
