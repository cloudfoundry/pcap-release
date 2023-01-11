// Package pcap provides types and interfaces to build a remote packet capturing
// tool. For details about the different applications see the different packages
// in `cmd/`.
package pcap

import (
	"fmt"
	"unicode"

	"go.uber.org/zap"
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
	HeaderVcapID = "x-vcap-request-id"
)

var (
	errNilField         = fmt.Errorf("field is nil")
	errEmptyField       = fmt.Errorf("field is empty")
	errInvalidPayload   = fmt.Errorf("invalid payload")
	errIllegalCharacter = fmt.Errorf("illegal character")
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

// purge reads all messages from the given channel and discards them. The
// discarded messages are logged on the trace level.
func purge[T any](c <-chan T) {
	for m := range c {
		zap.L().Warn("draining channel: discarding message", zap.Any("message", m))
	}
}

// newMessageResponse wraps the message msg of type t into a CaptureResponse, which can be sent to the recipient.
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

// newPacketResponse wraps data into a CaptureResponse, which can be sent to the recipient.
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

	err := validateDevice(opts.Device)
	if err != nil {
		return err
	}

	if len(opts.Filter) > 1000 {
		return fmt.Errorf("expected filter to be less than 1000 characters")
	}

	if opts.SnapLen == 0 {
		return fmt.Errorf("expected snaplen to be not zero")
	}
	return nil
}

// validateDevice is a go implementation of dev_valid_name from the linux kernel.
//
// See: https://lxr.linux.no/linux+v6.0.9/net/core/dev.c#L995
func validateDevice(name string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("validate device: %w", err)
		}
	}()

	if len(name) > 16 {
		return fmt.Errorf("name too long: %d > 16", len(name))
	}

	if name == "." || name == ".." {
		return fmt.Errorf("invalid name: '%s'", name)
	}

	for i, r := range name {
		if r == '/' {
			return fmt.Errorf("%w at pos. %d: '/'", errIllegalCharacter, i)
		}
		if r == '\x00' {
			return fmt.Errorf("%w at pos. %d: '\\0'", errIllegalCharacter, i)
		}
		if r == ':' {
			return fmt.Errorf("%w at pos. %d: ':'", errIllegalCharacter, i)
		}
		if unicode.Is(unicode.White_Space, r) {
			return fmt.Errorf("%w: whitespace at pos %d", errIllegalCharacter, i)
		}
	}

	return nil
}
