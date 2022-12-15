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

// docker image build -f agent.Dockerfile -t pcap:agent .
// docker image build -f api.Dockerfile -t pcap:api .
// docker network create pcap
// for i in {1..4}; do docker container run --rm -d --name pcap-agent-$i --network pcap pcap:agent; done
// docker container run -d --rm --name pcap-api --network pcap -v "$(pwd)/static-targets.json:/usr/local/etc/static-targets.json" -v "$(pwd)/cmd/api/.api.config.yml:/usr/local/etc/pcap-api.yml" -e PCAP_TARGETS=/usr/local/etc/static-targets.json -p 8080:8080 pcap:api

// then run the bosh.go as client. It will capture 100 responses and then gracefully close the connection from the client side.

const (
	// CompatibilityLevel indicates whether two parties are compatible. Once there is a change
	// that requires both parties to be updated this value MUST be incremented by one. The calling
	// party has to ensure that the compatibility level of the called party is equal or larger and
	// refuse operation if it isn't.
	CompatibilityLevel = 0

	// LogKeyVcapId sets on which field the vcap request id will be logged.
	LogKeyVcapId = "vcap-id"
)

var (
	errNilField       = fmt.Errorf("field is nil")
	errInvalidPayload = fmt.Errorf("invalid payload")
)

// BufferConf allows to specify the behaviour of buffers.
// TODO: can this be re-used within the pcap-api?
type BufferConf struct {
	// Size is the number of responses that can be buffered per stream.
	Size int `yaml:"size" validate:"gte=0"`
	// UpperLimit controls when the agent will start discarding messages.
	// The condition is len(buf) >= UpperLimit
	UpperLimit int `yaml:"upperLimit" validate:"gte=0,ltefield=Size"`
	// LowerLimit controls when the agent will stop discarding messages.
	// The condition is len(buf) <= LowerLimit
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

		// FIXME: Disabled metric as this led to an error of 'unknown metric'
		// MetricsServer().MessageDrained()
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
