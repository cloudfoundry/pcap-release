package pcap

// This file provides an early implementation of go1.20s context implementation.
// It adds functionality to cancel a context with a cause and retrieve that cause
// later. This is useful if you need concurrent programs to communicate the original
// error that caused the execution to stop.
// FIXME(maxmoehl): refactor to stdlib

import (
	"context"
	"sync/atomic"
)

// &cancelCauseKey is the key at which the cause for cancellation is stored. Since we use the pointer as a key
// we ensure that it is unique.
var cancelCauseKey int

// CancelCauseFunc is context.CancelCauseFunc in go1.20rc1.
// See: https://pkg.go.dev/context@go1.20rc1#CancelCauseFunc
type CancelCauseFunc func(cause error)

// WithCancelCause is context.WithCancelCause in go1.20rc1.
// See: https://pkg.go.dev/context@go1.20rc1#WithCancelCause
func WithCancelCause(parent context.Context) (context.Context, CancelCauseFunc) {
	cause := atomic.Pointer[error]{}

	ctx := context.WithValue(parent, &cancelCauseKey, &cause)

	ctx, cancel := context.WithCancel(ctx)

	return ctx, func(err error) {
		// see: https://cs.opensource.google/go/go/+/refs/tags/go1.20rc1:src/context/context.go;l=457-459
		if err == nil {
			err = context.Canceled
		}
		if cause.Load() == nil {
			cause.Store(&err)
		}
		cancel()
	}
}

// Cause is context.Cause in go1.20rc1.
// See: https://pkg.go.dev/context@go1.20rc1#Cause
func Cause(ctx context.Context) error {
	c, ok := ctx.Value(&cancelCauseKey).(*atomic.Pointer[error])
	if !ok {
		return nil
	}
	pErr := c.Load()
	if pErr == nil {
		return nil
	}
	return *pErr
}
