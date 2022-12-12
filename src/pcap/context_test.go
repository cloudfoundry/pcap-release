package pcap

import (
	"context"
	"fmt"
	"testing"
)

func TestCancelCauseWorks(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := WithCancelCause(ctx)

	originalErr := fmt.Errorf("something")
	cancel(originalErr)

	<-ctx.Done()

	err := Cause(ctx)
	if err != originalErr {
		t.Errorf("expected returned err and originalErr to be the same")
	}
}

func TestCancelCauseReturnsFirstError(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := WithCancelCause(ctx)

	originalErr := fmt.Errorf("something")
	cancel(originalErr)
	cancel(fmt.Errorf("unrelated error"))

	<-ctx.Done()

	err := Cause(ctx)
	if err != originalErr {
		t.Errorf("expected returned err and originalErr to be the same")
	}
}
