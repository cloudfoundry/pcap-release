// Package pcap provides types and interfaces to build a remote packet capturing
// tool. For details about the different applications see the different packages
// in `cmd/`.
package pcap

import (
	"fmt"
	"unicode"

	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
)

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative pcap.proto

const (
	// CompatibilityLevel indicates whether two parties are compatible. Once there is a change
	// that requires both parties to be updated this value MUST be incremented by one. The calling
	// party has to ensure that the compatibility level of the called party is equal or larger and
	// refuse operation if it isn't.
	CompatibilityLevel int64 = 0

	// LogKeyVcapID sets on which field the vcap request id will be logged.
	LogKeyVcapID = "vcap-id"
	HeaderVcapID = "x-vcap-request-id"
)

var (
	errNilField       = fmt.Errorf("field is nil")
	errInvalidPayload = fmt.Errorf("invalid payload")
)

// BufferConf allows to specify the behaviour of buffers.
//
// The recommendation is to set the upper limit slightly below the size
// to account for data put into the buffer while checking the fill condition
// or performing work. The lower limit should be low enough to make some room
// for new data but not too low (which would cause a lot of data to be
// discarded). After all the buffer should mainly soften short spikes in data
// transfer and these limits only protect against uncontrolled back pressure.
type BufferConf struct {
	// Size is the number of responses that can be buffered per stream.
	Size int `yaml:"size" validate:"gte=0"`
	// UpperLimit tells the manager of the buffer to start discarding messages
	// once the limit is exceeded. The condition looks like this:
	//   len(buf) >= UpperLimit
	UpperLimit int `yaml:"upperLimit" validate:"gte=0,ltefield=Size"`
	// LowerLimit tells the manager of the buffer to stop discarding messages
	// once the limit is reached/undercut. The condition looks like this:
	//   len(buf) <= LowerLimit
	LowerLimit int `yaml:"lowerLimit" validate:"gte=0,ltefield=UpperLimit"`
}

func (bc BufferConf) validate() error {
	return validator.New().Struct(bc)
}

// drain reads all messages from the given channel and discards them. The
// discarded messages are logged on the trace level.
func drain[T any](c <-chan T) {
	for m := range c {
		zap.L().Warn("discarding message", zap.Any("message", m))
	}
}

// newMessageResponse is a wrapper to clean up the code from these large struct
// definitions.
func newMessageResponse(t MessageType, msg string) *CaptureResponse {
	return &CaptureResponse{
		Payload: &CaptureResponse_Message{
			Message: &Message{
				Type:    t,
				Message: msg,
			},
		},
	}
}

// newPacketResponse is a wrapper to clean up the code from these large struct
// definitions.
func newPacketResponse(data []byte) *CaptureResponse {
	return &CaptureResponse{
		Payload: &CaptureResponse_Packet{
			Packet: &Packet{
				Data: data,
			},
		},
	}
}

func (opts *CaptureOptions) validate() error {
	if opts.Device == "" {
		return fmt.Errorf("expected device to be not empty string")
	}

	if !isAlphanumeric(opts.Device) {
		return fmt.Errorf("expected device name to be alphanumeric string")
	}

	// TODO: what validations we need for filters

	if opts.SnapLen == 0 {
		return fmt.Errorf("expected snaplen to be not zero")
	}
	return nil
}

func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
