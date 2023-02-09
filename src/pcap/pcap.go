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
	LogKeyVcapID = "vcap-id"
	HeaderVcapID = "x-vcap-request-id"
)

var (
	errValidationFailed = fmt.Errorf("validation failed")
	errNilField         = fmt.Errorf("field is nil: %w", errValidationFailed)
	errEmptyField       = fmt.Errorf("field is empty: %w", errValidationFailed)
	errInvalidPayload   = fmt.Errorf("invalid payload: %w", errValidationFailed)
	errIllegalCharacter = fmt.Errorf("illegal character: %w", errValidationFailed)
	errNoMetadata       = fmt.Errorf("no metadata")
	errNoVcapId         = fmt.Errorf("no vcap-id")
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

// setVcapID expands log to include the vcap-id extracted from ctx, if available.
//
// When no vcap-id is defined in ctx, a new random GUID is generated and set in ctx and the logger.
func setVcapID(ctx context.Context, log *zap.Logger) (context.Context, *zap.Logger) {
	vcapID, err := vcapIDFromCtx(ctx)

	if err != nil {
		// No existing vcap-id found, creating a new one and adding it to the context.
		newVcapID := uuid.Must(uuid.NewRandom()).String()
		vcapID = &newVcapID
		ctx = metadata.AppendToOutgoingContext(ctx, HeaderVcapID, *vcapID)

		if errors.Is(err, errNoMetadata) {
			defer log.Warn("request does not contain metadata, generated new vcap request id")
		}
		if errors.Is(err, errNoVcapId) {
			defer log.Warn("request does not contain request id, generating one")
		}
	}

	return ctx, log.With(zap.String(LogKeyVcapID, *vcapID))
}

// vcapIdFromCtx finds the vcap-id from the context metadata, if available.
//
// returns errNoMetadata if no metadata was found
// returns errNoVcapId if no vcap-id was found in the metadata
func vcapIDFromCtx(ctx context.Context) (*string, error) {
	md, ok := metadata.FromIncomingContext(ctx)

	if !ok {
		return nil, errNoMetadata
	}

	if ok {
		vcapReqIDs := md.Get(HeaderVcapID)

		if len(vcapReqIDs) > 0 {
			vcapID := vcapReqIDs[0]
			return &vcapID, nil
		}
	}

	return nil, errNoVcapId
}

// interfaceAddrs provides a list of all known network addresses
var interfaceAddrs = net.InterfaceAddrs

// containsForbiddenRunes checks whether a given string contains
// any character that is less than 32 or more than 126.
//
// See: https://www.lookuptables.com/text/ascii-table
func containsForbiddenRunes(in string) bool {
	for _, r := range []rune(in) {
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
	} else {
		return fmt.Sprintf("not (%s) and (%s)", apiFilter, filter), nil
	}
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

	var ips []string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		// check that:
		// * ipNet is actually an IP address
		// * it is not a loopback address
		// * can be represented in either 4- or 16-bytes representation
		if ok && !ipNet.IP.IsLoopback() && (ipNet.IP.To4() != nil || ipNet.IP.To16() != nil) {
			ips = append(ips, ipNet.IP.String())
		}
	}

	var ipFilters []string
	for _, ip := range ips {
		ipFilters = append(ipFilters, fmt.Sprintf("ip host %s", ip))
	}

	return strings.Join(ipFilters, " or "), nil
}
