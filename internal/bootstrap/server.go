package bootstrap

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/DIMO-Network/tesla-oracle/internal/app"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/middleware"
	"github.com/DIMO-Network/tesla-oracle/internal/rpc"
	grpc_oracle "github.com/DIMO-Network/tesla-oracle/pkg/grpc"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

// ServerManager manages all application servers
type ServerManager struct {
	settings      *config.Settings
	logger        *zerolog.Logger
	services      *Services
	monitoringApp *fiber.App
	webApp        *fiber.App
	grpcServer    *grpc.Server
}

// NewServerManager creates a new server manager
func NewServerManager(settings *config.Settings, logger *zerolog.Logger, services *Services) *ServerManager {
	return &ServerManager{
		settings: settings,
		logger:   logger,
		services: services,
	}
}

// Initialize sets up all servers
func (sm *ServerManager) Initialize() error {
	// Create monitoring server
	sm.monitoringApp = sm.createMonitoringServer()

	// Create web application
	sm.webApp = app.App(
		sm.settings,
		sm.logger,
		sm.services.IdentityService,
		sm.services.OnboardingService,
		sm.services.RiverClient,
		sm.services.WalletService,
		sm.services.TransactionsClient,
		sm.services.Repositories,
		sm.services.TeslaService,
	)

	// Create gRPC server
	sm.grpcServer = sm.createGRPCServer()

	return nil
}

// StartAll starts all servers
func (sm *ServerManager) StartAll(ctx context.Context, group *errgroup.Group) {
	useLocalTLS := sm.settings.Environment == "local" && sm.settings.UseLocalTLS

	// Start monitoring server
	sm.logger.Info().Str("port", strconv.Itoa(sm.settings.MonPort)).Msgf("Starting monitoring server on port %d", sm.settings.MonPort)
	sm.startFiberApp(ctx, sm.monitoringApp, fmt.Sprintf(":%d", sm.settings.MonPort), group, useLocalTLS)

	// Start web server
	sm.logger.Info().Str("port", strconv.Itoa(sm.settings.WebPort)).Msgf("Starting web server %d", sm.settings.WebPort)
	sm.startFiberApp(ctx, sm.webApp, ":"+strconv.Itoa(sm.settings.WebPort), group, useLocalTLS)

	// Start gRPC server
	group.Go(func() error {
		return sm.startGRPCServer()
	})

	// Graceful shutdown for gRPC
	group.Go(func() error {
		<-ctx.Done()
		sm.grpcServer.GracefulStop()
		return nil
	})
}

// createMonitoringServer creates the monitoring/metrics server
func (sm *ServerManager) createMonitoringServer() *fiber.App {
	monApp := fiber.New(fiber.Config{DisableStartupMessage: true})
	monApp.Get("/", func(c *fiber.Ctx) error {
		return nil
	})
	monApp.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))
	return monApp
}

// createGRPCServer creates the gRPC server with middleware
func (sm *ServerManager) createGRPCServer() *grpc.Server {
	mdw := middleware.New(sm.logger)

	server := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			mdw.MetricsMiddleware(),
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_prometheus.UnaryServerInterceptor,
			grpc_recovery.UnaryServerInterceptor([]grpc_recovery.Option{
				grpc_recovery.WithRecoveryHandler(mdw.PanicMiddleware()),
			}...),
		)),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	)

	teslaSvc := rpc.NewTeslaRPCService(sm.services.DB.DBS, sm.logger, sm.services.WalletService)
	grpc_oracle.RegisterTeslaOracleServer(server, teslaSvc)

	return server
}

// startFiberApp starts a Fiber application with graceful shutdown
func (sm *ServerManager) startFiberApp(ctx context.Context, fiberApp *fiber.App, addr string, group *errgroup.Group, useLocalTLS bool) {
	group.Go(func() error {
		sm.logger.Info().Msgf("starting FiberApp: %s", addr)

		if useLocalTLS {
			sm.logger.Info().Msgf("using local TLS")
			if err := fiberApp.ListenTLS("0.0.0.0"+addr, "./web/.mkcert/cert.pem", "./web/.mkcert/dev.pem"); err != nil {
				return fmt.Errorf("failed to start server: %w", err)
			}
		} else {
			if err := fiberApp.Listen(addr); err != nil {
				return fmt.Errorf("failed to start server: %w", err)
			}
		}
		return nil
	})

	group.Go(func() error {
		<-ctx.Done()
		sm.logger.Info().Msgf("shutting down FiberApp: %s", addr)
		if err := fiberApp.Shutdown(); err != nil {
			return fmt.Errorf("failed to shutdown server: %w", err)
		}
		return nil
	})
}

// startGRPCServer starts the gRPC server
func (sm *ServerManager) startGRPCServer() error {
	sm.logger.Info().Msgf("Starting gRPC server on port %d", sm.settings.GRPCPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", sm.settings.GRPCPort))
	if err != nil {
		return fmt.Errorf("couldn't listen on gRPC port %d: %w", sm.settings.GRPCPort, err)
	}

	if err := sm.grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("gRPC server terminated unexpectedly: %w", err)
	}
	return nil
}
