// Package observability provides OpenTelemetry-based monitoring and tracing.
package observability

import (
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// TelemetryConfig holds configuration for observability.
type TelemetryConfig struct {
	ServiceName    string
	ServiceVersion string
	Enabled        bool
	OTLPEndpoint   string  // e.g., "localhost:4317" for OTLP gRPC
	SampleRate     float64 // 1.0 = all traces, 0.1 = 10%
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() *TelemetryConfig {
	return &TelemetryConfig{
		ServiceName:    "behemoth",
		ServiceVersion: "dev",
		Enabled:        true,
		OTLPEndpoint:   "localhost:4317",
		SampleRate:     0.5,
	}
}

// Telemetry provides observability functionality.
type Telemetry struct {
	config    *TelemetryConfig
	tracer    trace.Tracer
	meter     metric.Meter
	counter   metric.Int64Counter
	histogram metric.Float64Histogram
}

// New creates a new Telemetry instance.
func New(cfg *TelemetryConfig) (*Telemetry, error) {
	t := &Telemetry{config: cfg}

	if !cfg.Enabled {
		return t, nil
	}

	// Get global tracer provider
	t.tracer = otel.Tracer(cfg.ServiceName)

	// Get global meter provider
	meter := otel.Meter(cfg.ServiceName)
	t.meter = meter

	// Create counters and histograms
	var err error
	t.counter, err = meter.Int64Counter("behemoth.operations.total")
	if err != nil {
		return nil, fmt.Errorf("create counter: %w", err)
	}

	t.histogram, err = meter.Float64Histogram("behemoth.operation.duration.ms")
	if err != nil {
		return nil, fmt.Errorf("create histogram: %w", err)
	}

	return t, nil
}
