package pcap

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	errTestEnded         = fmt.Errorf("test ended")
	errContextCancelled  = fmt.Errorf("context error")
	errDiscardedMsg      = fmt.Errorf("discarding packets")
	ErrValidationFailed  = fmt.Errorf("validation failed")
	errNilField          = fmt.Errorf("field is nil: %w", ErrValidationFailed)
	errEmptyField        = fmt.Errorf("field is empty: %w", ErrValidationFailed)
	errInvalidPayload    = fmt.Errorf("invalid payload: %w", ErrValidationFailed)
	errIllegalCharacter  = fmt.Errorf("illegal character: %w", ErrValidationFailed)
	errNoVcapID          = fmt.Errorf("no vcap-id")
	errTooManyCaptures   = fmt.Errorf("too many concurrent captures")
	errDraining          = fmt.Errorf("draining")
	errUnexpectedMessage = fmt.Errorf("unexpected message")
	ErrNoEndpoints       = fmt.Errorf("no matching endpoints found")
	ErrNotConnected      = fmt.Errorf("client not connected to api")
	ErrResolverUnhealthy = fmt.Errorf("resolver unhealthy")
	ErrNotAuthorized     = fmt.Errorf("not authorized")
	ErrTokenUnsupported  = fmt.Errorf("token unsupported: %w", ErrNotAuthorized)
)

// pcapError is an attempt to work around the shortcomings of error handling in the gRPC
// library. It's gRPC status compatible and supports unwrapping (if an error has been
// wrapped).
// Use errorf to construct a new error.
type pcapError struct {
	status *status.Status
	inner  error
}

func (e pcapError) GRPCStatus() *status.Status {
	return e.status
}

func (e pcapError) Error() string {
	return e.status.Message()
}

func (e pcapError) Unwrap() error {
	return e.inner
}

// errorf creates a new error that is compatible with gRPC status and has support for
// wrapping errors. It works like fmt.Errorf (because that's what's used under the hood).
func errorf(c codes.Code, format string, a ...interface{}) error {
	// we simply utilize fmt.Errorf instead of struggling with a custom implementation
	e := fmt.Errorf(format, a...)
	return pcapError{
		status: status.New(c, e.Error()),
		// if something has been wrapped, get it
		inner: errors.Unwrap(e),
	}
}
