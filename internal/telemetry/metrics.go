package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var batchRequestDuration = promauto.NewHistogram(
	prometheus.HistogramOpts{
		Namespace: "tesla_oracle",
		Subsystem: "telemetry",
		Name:      "batch_request_duration_seconds",
		Buckets:   []float64{.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500},
	},
)

var totalWindowProcessingDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Namespace: "tesla_oracle",
		Subsystem: "telemetry",
		Name:      "total_window_processing_duration_seconds",
		Buckets:   []float64{.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500},
	},
	[]string{"status"},
)

var vehiclesTransmittingData = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "telemetry",
		Name:      "vehicles_transmitting_data",
	},
)

var batchSize = promauto.NewCounter(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "telemetry",
		Name:      "batch_size",
	},
)

var requestCount = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "tesla_oracle",
		Subsystem: "telemetry",
		Name:      "dis_request_count",
		Help:      "The total number of DIS requests",
	},
	[]string{"status"},
)
