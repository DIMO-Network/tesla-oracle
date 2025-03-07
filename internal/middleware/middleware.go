package middleware

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	GRPCRequestCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rpc_request_count",
			Help: "The total number of requests served by the GRPC Server",
		},
		[]string{"method", "status"},
	)

	GRPCPanicCount = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "tesla_oracle_grpc_panic_count",
			Help: "The total number of panics served by the GRPC Server",
		},
	)

	GRPCResponseTime = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "tesla_oracle_grpc_response_time",
			Help:    "The response time distribution of the GRPC Server",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"method", "status"},
	)
)

func New(logger *zerolog.Logger) *Middleware {
	return &Middleware{
		logger: logger,
	}
}

type Middleware struct {
	logger *zerolog.Logger
}

func (m *Middleware) MetricsMiddleware() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		startTime := time.Now()
		resp, err := handler(ctx, req)

		if err != nil {
			if s, ok := status.FromError(err); ok {
				GRPCResponseTime.With(prometheus.Labels{"method": info.FullMethod, "status": s.Code().String()}).Observe(time.Since(startTime).Seconds())
				GRPCRequestCount.With(prometheus.Labels{"method": info.FullMethod, "status": s.Code().String()}).Inc()
			} else {
				GRPCResponseTime.With(prometheus.Labels{"method": info.FullMethod, "status": "unknown"}).Observe(time.Since(startTime).Seconds())
				GRPCRequestCount.With(prometheus.Labels{"method": info.FullMethod, "status": "unknown"}).Inc()
			}
		} else {
			GRPCResponseTime.With(prometheus.Labels{"method": info.FullMethod, "status": "OK"}).Observe(time.Since(startTime).Seconds())
			GRPCRequestCount.With(prometheus.Labels{"method": info.FullMethod, "status": "OK"}).Inc()
		}

		return resp, err
	}
}

func (m *Middleware) PanicMiddleware() grpc_recovery.RecoveryHandlerFunc {
	return func(p any) (err error) {
		GRPCPanicCount.Inc()

		m.logger.Err(fmt.Errorf("%s", p)).Str("stack", string(debug.Stack())).Msg("grpc recovered from panic")
		return status.Errorf(codes.Internal, "%s", p)
	}
}
