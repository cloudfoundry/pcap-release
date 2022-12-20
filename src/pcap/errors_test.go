package pcap

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestErrorfWrapsProperly(t *testing.T) {
	innerErr := errors.New("something")
	err := errorf(codes.Unknown, "some error: %w", innerErr)

	wrappedErr := errors.Unwrap(err)

	//nolint:errorlint // we want to check if it is the same error as in: it is the same address
	if wrappedErr != innerErr {
		t.Fatalf("expected err to wrap innerErr")
	}
}

func TestErrorfSupportGrpcStatus(t *testing.T) {
	err := errorf(codes.DataLoss, "some error")

	code := status.Code(err)

	if code != codes.DataLoss {
		t.Fatalf("expected error to contain codes.DataLoss")
	}
}

func Test_pcapError_Error(t *testing.T) {
	tests := []struct {
		name   string
		format string
		args   []any
	}{
		{
			"no format",
			"some error",
			nil,
		},
		{
			"simple format",
			"some error %d %s",
			[]interface{}{5, "foo"},
		},
		{
			"with embedded error",
			"some error %w",
			[]interface{}{fmt.Errorf("foo bar")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errorf(codes.Unknown, tt.format, tt.args...).Error()
			want := fmt.Errorf(tt.format, tt.args...).Error()

			if got != want {
				t.Errorf("Error() = %v, want %v", got, want)
			}
		})
	}
}
