package observability

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// StartSpan begins a new traced span.
//
// When telemetry is disabled the returned span must still be a usable no-op:
// a nil trace.Span interface panics on the deferred span.End() in
// TracedFunction (and any other defer-End caller). SpanFromContext hands back
// the noop span installed by the default global provider instead.
func (t *Telemetry) StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if !t.config.Enabled {
		return ctx, trace.SpanFromContext(ctx)
	}
	return t.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// RecordSuccess records a successful operation.
func (t *Telemetry) RecordSuccess(ctx context.Context, operation string, duration time.Duration) {
	if !t.config.Enabled || t.counter == nil || t.histogram == nil {
		return
	}
	t.counter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("operation", operation),
		attribute.String("status", "success"),
	))
	t.histogram.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(
		attribute.String("operation", operation),
	))
}

// RecordError records a failed operation.
func (t *Telemetry) RecordError(ctx context.Context, operation string, duration time.Duration, err error) {
	if !t.config.Enabled || t.counter == nil || t.histogram == nil {
		return
	}
	t.counter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("operation", operation),
		attribute.String("status", "error"),
		attribute.String("error_type", typeof(err)),
	))
	t.histogram.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(
		attribute.String("operation", operation),
		attribute.String("status", "error"),
	))
}

// SetSpanError marks a span as errored.
func SetSpanError(span trace.Span, err error) {
	if span == nil {
		return
	}
	span.SetStatus(codes.Error, err.Error())
	span.RecordError(err)
}

// SpanFromContext gets the current span from context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// AddAttributes adds attributes to the current span.
func AddAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attrs...)
}

// TracedFunction wraps a function with tracing.
func (t *Telemetry) TracedFunction(ctx context.Context, name string, fn func(ctx context.Context) error) error {
	ctx, span := t.StartSpan(ctx, name)
	defer span.End()

	start := time.Now()
	err := fn(ctx)
	duration := time.Since(start)

	if err != nil {
		SetSpanError(span, err)
		t.RecordError(ctx, name, duration, err)
	} else {
		t.RecordSuccess(ctx, name, duration)
	}

	return err
}

func typeof(v interface{}) string {
	// The concrete type is what makes an error_type label useful: every error
	// satisfies error, so the label was previously one constant value and could
	// not distinguish net timeouts from JSON decode failures.
	return fmt.Sprintf("%T", v)
}
