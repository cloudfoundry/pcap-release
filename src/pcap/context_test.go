package pcap

import (
	"context"
	"fmt"
	"io"
	"testing"
)

func TestCancelCauseWorks(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := WithCancelCause(ctx)

	originalErr := fmt.Errorf("something")
	cancel(originalErr)

	<-ctx.Done()

	err := Cause(ctx)
	if err != originalErr { //nolint:errorlint // we want to check if it is the same error as in: it is the same address
		t.Errorf("expected returned err and originalErr to be the same")
	}
}

func TestCancelCauseReturnsFirstError(t *testing.T) {
	ctx, cancel := WithCancelCause(context.Background())

	originalErr := fmt.Errorf("something")
	cancel(originalErr)
	cancel(fmt.Errorf("unrelated error"))

	<-ctx.Done()

	err := Cause(ctx)
	if err != originalErr { //nolint:errorlint // we want to check if it is the same error as in: it is the same address
		t.Errorf("expected returned err and originalErr to be the same")
	}
}

func TestCause(t *testing.T) {
	tests := []struct {
		name    string
		ctx     func() context.Context
		wantErr error
	}{
		{
			"not cancelled",
			context.Background,
			nil,
		},
		{
			"cancelled without cause",
			func() context.Context {
				ctx, cancel := WithCancelCause(context.Background())
				cancel(nil)
				<-ctx.Done()
				return ctx
			},
			context.Canceled,
		},
		{
			"cancelled with cause",
			func() context.Context {
				ctx, cancel := WithCancelCause(context.Background())
				cancel(io.EOF)
				<-ctx.Done()
				return ctx
			},
			io.EOF,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Cause(tt.ctx()); err != tt.wantErr { //nolint:errorlint // we want to make sure exactly the same error is returned
				t.Errorf("Cause() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
