package pcap

import (
	"errors"
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
