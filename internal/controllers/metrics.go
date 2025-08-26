package controllers

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var teslaCodeFailureCount = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "tesla",
		Name:      "code_exchange_failures_total",
		Help:      "Known strains of failure during Tesla authorization code exchange and ensuing vehicle display.",
	},
	[]string{"type"},
)

var unsubscribeTelemetrySuccessCount = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "tesla",
		Name:      "unsubscribe_telemetry_success_total",
		Help:      "Total number of successful telemetry unsubscriptions.",
	},
)

var unsubscribeTelemetryFailureCount = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "tesla",
		Name:      "unsubscribe_telemetry_failure_total",
		Help:      "Total number of failed telemetry unsubscriptions.",
	},
)

var subscribeTelemetrySuccessCount = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "tesla",
		Name:      "subscribe_telemetry_success_total",
		Help:      "Total number of successful telemetry subscriptions.",
	},
)

var subscribeTelemetryFailureCount = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "tesla",
		Name:      "subscribe_telemetry_failure_total",
		Help:      "Total number of failed telemetry subscriptions.",
	},
)
