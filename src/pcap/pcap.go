// Package pcap provides types and interfaces to build a remote packet capturing
// tool. For details about the different applications see the different packages
// in `cmd/`.
package pcap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"go.uber.org/zap"
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
	LogKeyVcapID        = "vcap-id"
	HeaderVcapID        = "x-vcap-request-id"
	maxDeviceNameLength = 16
	maxFilterLength     = 5000
)

var (
	errValidationFailed = fmt.Errorf("validation failed")
	errNilField         = fmt.Errorf("field is nil: %w", errValidationFailed)
	errEmptyField       = fmt.Errorf("field is empty: %w", errValidationFailed)
	errInvalidPayload   = fmt.Errorf("invalid payload: %w", errValidationFailed)
	errIllegalCharacter = fmt.Errorf("illegal character: %w", errValidationFailed)
	errNoMetadata       = fmt.Errorf("no metadata")
	errNoVcapID         = fmt.Errorf("no vcap-id")
	errTooManyCaptures  = fmt.Errorf("too many concurrent captures")
	errDraining         = fmt.Errorf("draining")
)

// purge reads all messages from the given channel and discards them. The
// discarded messages are logged on the trace level.
func purge[T any](c <-chan T) {
	for m := range c {
		zap.L().Warn("draining channel: discarding message", zap.Any("message", m))
	}
}

// newMessageResponse wraps the message msg of type t into a CaptureResponse, which can be sent to the recipient.
func newMessageResponse(t MessageType, msg string, origin string) *CaptureResponse {
	return &CaptureResponse{
		Payload: &CaptureResponse_Message{
			Message: &Message{
				Type:    t,
				Message: msg,
				Origin:  origin,
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

	if len(opts.Filter) > maxFilterLength {
		return fmt.Errorf("expected filter to be less than 5000 characters, received %d", len(opts.Filter))
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

	if len(name) > maxDeviceNameLength {
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

// setVcapID expands log to include the vcap-id extracted from ctx, if available and copy vcap-id to
// outgoing context of metadata.
// When no vcap-id is defined in ctx, a new random GUID is generated and set in outgoing context of metadata and the logger.
func setVcapID(ctx context.Context, log *zap.Logger, externalVcapID *string) (context.Context, *zap.Logger) {
	vcapID, err := vcapIDFromIncomingCtx(ctx)

	if err != nil {
		if errors.Is(err, errNoMetadata) {
			ctx = metadata.NewOutgoingContext(ctx, metadata.MD{})
		}
		if externalVcapID != nil {
			vcapID = externalVcapID
		} else {
			// No existing vcap-id found, creating a new one and adding it to the context.
			newVcapID := uuid.Must(uuid.NewRandom()).String()
			vcapID = &newVcapID
		}
	}
	// outgoing context is current context
	ctx = metadata.AppendToOutgoingContext(ctx, HeaderVcapID, *vcapID)

	log = log.With(zap.String(LogKeyVcapID, *vcapID))

	if errors.Is(err, errNoMetadata) {
		log.Warn("request does not contain metadata, generated new vcap request id")
	}
	if errors.Is(err, errNoVcapID) {
		log.Warn("request does not contain request id, generating one")
	}

	return ctx, log
}

// vcapIDFromOutgoingCtx finds the vcap-id from the context metadata, always set by pcap
//
// returns errNoMetadata if no metadata was found
// returns errNoVcapID if no vcap-id was found in the metadata.
func vcapIDFromOutgoingCtx(ctx context.Context) (*string, error) {
	var vcap *string
	var err error
	if md, ok := metadata.FromOutgoingContext(ctx); ok {
		vcap, err = getVcapFromMD(md)
		if err == nil {
			return vcap, nil
		} else {
			return nil, err
		}
	}

	return nil, errNoMetadata
}

// vcapIDFromIncomingCtx finds the vcap-id from the context metadata, if available.
//
// returns errNoMetadata if no metadata was found
// returns errNoVcapID if no vcap-id was found in the metadata.
func vcapIDFromIncomingCtx(ctx context.Context) (*string, error) {
	var vcap *string
	var err error
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		vcap, err = getVcapFromMD(md)
		if err == nil {
			return vcap, nil
		} else {
			return nil, err
		}
	}
	return nil, errNoMetadata
}

func getVcapFromMD(md metadata.MD) (*string, error) {
	vcapReqIDs := md.Get(HeaderVcapID)

	if len(vcapReqIDs) > 0 {
		vcapID := vcapReqIDs[0]
		return &vcapID, nil
	}
	return nil, errNoVcapID
}

// interfaceAddrs provides a list of all known network addresses.
var interfaceAddrs = net.InterfaceAddrs

// containsForbiddenRunes checks whether a given string contains
// any character that is less than 32 or more than 126.
//
// See: https://www.lookuptables.com/text/ascii-table
func containsForbiddenRunes(in string) bool {
	for _, r := range in {
		if r < 32 || r > 126 {
			return true
		}
	}
	return false
}

// patchFilter extends the given filter by excluding the filter generated
// by generateApiFilter.
func patchFilter(filter string) (string, error) {
	apiFilter, err := generateAPIFilter()
	if err != nil {
		return "", err
	}

	filter = strings.TrimSpace(filter)

	if filter == "" {
		return fmt.Sprintf("not (%s)", apiFilter), nil
	}

	return fmt.Sprintf("not (%s) and (%s)", apiFilter, filter), nil
}

// generateApiFilter takes all IP addresses as returned by interfaceAddrs and
// generates a filter for those IP addresses (loopback is excluded from the filter).
// Note: the filter *matches* all of those IP addresses.
func generateAPIFilter() (string, error) {
	addrs, err := interfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("unable to get IPs: %w", err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("unable to determine ip addresses")
	}

	var ipFilters []string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		// check that:
		// * ipNet is actually an IP address
		// * it is not a loopback address
		// * can be represented in either 4- or 16-bytes representation
		if ok && !ipNet.IP.IsLoopback() {
			v4 := ipNet.IP.To4() != nil
			v6 := !v4 && ipNet.IP.To16() != nil

			expression := "ip"
			if !v4 && !v6 {
				return "", fmt.Errorf("address %s is not IPv4 or v6", ipNet.IP.String())
			}
			if v6 {
				expression = "ip6"
			}

			ipFilters = append(ipFilters, fmt.Sprintf("%s host %s", expression, ipNet.IP.String()))
		}
	}
	return strings.Join(ipFilters, " or "), nil
}

// makeStopRequest creates the generic stop CaptureRequest that can be sent to api and agent.
func makeStopRequest() *CaptureRequest {
	return &CaptureRequest{Operation: &CaptureRequest_Stop{Stop: &StopCapture{}}}
}
