package observability

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// With telemetry disabled StartSpan used to return a nil trace.Span interface,
// which panics on the deferred span.End() inside TracedFunction. The disabled
// path must hand back the noop span from the context instead.
func TestDisabledTelemetryNeverPanics(t *testing.T) {
	tel := &Telemetry{config: &TelemetryConfig{Enabled: false}}

	ctx, span := tel.StartSpan(context.Background(), "op")
	if span == nil {
		t.Fatal("StartSpan must not return a nil span interface when disabled")
	}
	span.End() // panics before the fix

	err := tel.TracedFunction(ctx, "op", func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("TracedFunction: %v", err)
	}
	err = tel.TracedFunction(ctx, "op", func(context.Context) error { return errors.New("boom") })
	if err == nil {
		t.Fatal("TracedFunction must propagate the error")
	}
	tel.RecordSuccess(ctx, "op", time.Millisecond)
	tel.RecordError(ctx, "op", time.Millisecond, errors.New("boom"))
}

// error_type must distinguish concrete error types — every error satisfies
// error, so the old switch collapsed all of them into one constant label.
func TestTypeofNamesTheConcreteType(t *testing.T) {
	if got := typeof(errors.New("x")); got != "*errors.errorString" {
		t.Fatalf("typeof(errors.New)=%q", got)
	}
	custom := &struct{ error }{}
	if got := typeof(custom); got == "error" || got == "unknown" {
		t.Fatalf("typeof must use the concrete type, got %q", got)
	}
}

// SetSpanError must tolerate a nil span (the disabled path of older callers).
func TestSetSpanErrorNilSafe(t *testing.T) {
	SetSpanError(nil, errors.New("boom"))
	if span := trace.SpanFromContext(context.Background()); span == nil {
		t.Fatal("SpanFromContext must return a non-nil noop span")
	}
}
