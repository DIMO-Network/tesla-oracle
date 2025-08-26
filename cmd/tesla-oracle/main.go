package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/DIMO-Network/go-transactions"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/shared/pkg/settings"
	"github.com/DIMO-Network/tesla-oracle/internal/app"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/consumer"
	"github.com/DIMO-Network/tesla-oracle/internal/middleware"
	"github.com/DIMO-Network/tesla-oracle/internal/onboarding"
	"github.com/DIMO-Network/tesla-oracle/internal/rpc"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	grpc_oracle "github.com/DIMO-Network/tesla-oracle/pkg/grpc"
	"github.com/IBM/sarama"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	// import docs for swagger generation.
	_ "github.com/DIMO-Network/tesla-oracle/docs"
)

// @title                       DIMO Tesla Oracle API
// @version                     1.0
// @securityDefinitions.apikey  BearerAuth
// @in                          header
// @name                        Authorization
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "tesla-oracle").
		Logger()

	settings, err := settings.LoadConfig[config.Settings]("settings.yaml")
	if err != nil {
		logger.Fatal().Err(err).Msg("could not load settings")
	}

	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		command := "up"
		if len(os.Args) > 2 {
			command = os.Args[2]
			if command == "down-to" || command == "up-to" {
				command = command + " " + os.Args[3]
			}
		}
		logger.Info().Msg("Starting migration")
		migrateDatabase(logger, &settings, command)
		logger.Info().Msg("Migration complete")
		return
	}

	pdb := db.NewDbConnectionFromSettings(ctx, &settings.DB, true)
	pdb.WaitForDB(logger)

	transactionsClient, err := onboarding.NewTransactionsClient(&settings)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create transactions client")
	}

	onboardingService := service.NewOnboardingService(&pdb, &logger)
	identityService := service.NewIdentityAPIService(&logger, &settings)
	deviceDefinitionsService := service.NewDeviceDefinitionsAPIService(&logger, &settings)

	walletService, err := service.NewSDWalletEnclaveClient(&logger, settings)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create SD Wallets service")
	}

	mdw := middleware.New(&logger)

	group, gCtx := errgroup.WithContext(ctx)

	riverClient, _, dbPool, err := createRiverClientWithWorkersAndPool(gCtx, logger, &settings, identityService, deviceDefinitionsService, &pdb, transactionsClient, walletService)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create river client, workers and db pool")
	}
	defer dbPool.Close()

	runRiver(gCtx, logger, riverClient, group)

	monApp := createMonitoringServer()
	webApp := app.App(&settings, &logger, identityService, deviceDefinitionsService, onboardingService, riverClient, walletService, transactionsClient, &pdb)

	useLocalTLS := settings.Environment == "local" && settings.UseLocalTLS

	logger.Info().Str("port", strconv.Itoa(settings.MonPort)).Msgf("Starting monitoring server on port %d", settings.MonPort)
	StartFiberApp(gCtx, monApp, fmt.Sprintf(":%d", settings.MonPort), group, &logger, useLocalTLS)

	logger.Info().Str("port", strconv.Itoa(settings.WebPort)).Msgf("Starting web server %d", settings.WebPort)
	StartFiberApp(gCtx, webApp, ":"+strconv.Itoa(settings.WebPort), group, &logger, useLocalTLS)

	teslaSvc := rpc.NewTeslaRPCService(pdb.DBS, &logger, walletService)
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

	grpc_oracle.RegisterTeslaOracleServer(server, teslaSvc)

	if settings.EnableContractEventConsumer {
		config := sarama.NewConfig()
		config.Version = sarama.V3_6_0_0
		logger.Info().Msgf("Starting gRPC server on port %d", settings.GRPCPort)
		cGroup, err := sarama.NewConsumerGroup([]string{settings.KafkaBrokers}, settings.TopicContractEvent, config)
		if err != nil {
			logger.Fatal().Err(err).Msg("error creating consumer from client")
		}

		proc := consumer.New(pdb, settings.TopicContractEvent, &logger)

		group.Go(func() error {
			if err := StartContractEventConsumer(gCtx, proc, cGroup, settings.TopicContractEvent, &logger); err != nil {
				return fmt.Errorf("error starting contract event consumer: %w", err)
			}

			return nil
		})
	}

	{
		config := sarama.NewConfig()
		config.Version = sarama.V3_6_0_0
		logger.Info().Msgf("Starting gRPC server on port %d", settings.GRPCPort)
		cGroup, err := sarama.NewConsumerGroup([]string{settings.KafkaBrokers}, "tesla-oracle", config)
		if err != nil {
			logger.Fatal().Err(err).Msg("error creating consumer from client")
		}

		cGroup.Consume()

		proc := consumer.New(pdb, settings.TopicContractEvent, &logger)

		group.Go(func() error {
			if err := StartContractEventConsumer(gCtx, proc, cGroup, settings.TopicContractEvent, &logger); err != nil {
				return fmt.Errorf("error starting contract event consumer: %w", err)
			}

			return nil
		})
	}

	group.Go(func() error {
		if err := StartGRPCServer(server, settings.GRPCPort, &logger); err != nil {
			return fmt.Errorf("error starting grpc server: %w", err)
		}

		return nil
	})

	group.Go(func() error {
		<-gCtx.Done()
		server.GracefulStop()
		return nil
	})

	if err := group.Wait(); err != nil {
		logger.Fatal().Err(err).Msg("Server error on shutdown.")
	}

	logger.Info().Msg("Gracefully shutting down and running cleanup tasks...")
	_ = ctx.Done()
	_ = pdb.DBS().Writer.Close()
	_ = pdb.DBS().Reader.Close()

}

func StartGRPCServer(server *grpc.Server, grpcPort int, logger *zerolog.Logger) error {
	logger.Info().Msgf("Starting gRPC server on port %d", grpcPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		return fmt.Errorf("couldn't listen on gRPC port %d: %w", grpcPort, err)
	}

	if err := server.Serve(lis); err != nil {
		return fmt.Errorf("gRPC server terminated unexpectedly: %w", err)
	}

	return nil
}

func StartContractEventConsumer(ctx context.Context, proc *consumer.Processor, consumer sarama.ConsumerGroup, topic string, logger *zerolog.Logger) error {
	for {
		logger.Info().Msgf("starting consumer: %s", topic)
		if err := consumer.Consume(ctx, []string{topic}, proc); err != nil {
			if errors.Is(err, sarama.ErrClosedConsumerGroup) {
				return nil
			}
			return err
		}
		if ctx.Err() != nil { // returning nil since this can only be context cancelled
			return nil
		}
	}
}

func StartFiberApp(ctx context.Context, fiberApp *fiber.App, addr string, group *errgroup.Group, logger *zerolog.Logger, useLocalTLS bool) {
	group.Go(func() error {
		logger.Info().Msgf("starting FiberApp: %s", addr)

		if useLocalTLS {
			logger.Info().Msgf("using local TLS")
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
		logger.Info().Msgf("shutting down FiberApp: %s", addr)
		if err := fiberApp.Shutdown(); err != nil {
			return fmt.Errorf("failed to shutdown server: %w", err)
		}
		return nil
	})
}

func createMonitoringServer() *fiber.App {
	monApp := fiber.New(fiber.Config{DisableStartupMessage: true})
	monApp.Get("/", func(c *fiber.Ctx) error {
		return nil
	})
	monApp.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))

	return monApp
}

func createRiverClientWithWorkersAndPool(ctx context.Context, logger zerolog.Logger, settings *config.Settings, identityService service.IdentityAPIService, dd service.DeviceDefinitionsAPIService, dbs *db.Store, tr *transactions.Client, ws service.SDWalletsAPI) (*river.Client[pgx.Tx], *river.Workers, *pgxpool.Pool, error) {
	workers := river.NewWorkers()

	// TODO: Create and register workers
	onboardingWorker := onboarding.NewOnboardingWorker(settings, logger, identityService, dbs, tr, ws)

	err := river.AddWorkerSafely(workers, onboardingWorker)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to add onboarding worker")
		return nil, nil, nil, err
	}
	logger.Debug().Msg("Added onboarding worker")

	dbURL := settings.DB.BuildConnectionString(true)
	dbPool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to database")
		return nil, nil, nil, err
	}

	logger.Debug().Msg("DB pool for workers created")

	riverClient, err := river.NewClient(riverpgxv5.New(dbPool), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: 100},
		},
		Workers: workers,
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create river client")
		return nil, nil, nil, err
	}

	return riverClient, workers, dbPool, err
}

func runRiver(ctx context.Context, logger zerolog.Logger, riverClient *river.Client[pgx.Tx], group *errgroup.Group) {
	runCtx := context.Background()

	group.Go(func() error {
		logger.Debug().Msg("Starting river client")
		if err := riverClient.Start(runCtx); err != nil {
			logger.Fatal().Err(err).Msg("failed to start river client")
		}
		return nil
	})
	group.Go(func() error {
		<-ctx.Done()
		logger.Debug().Msg("Stopping river client")
		if err := riverClient.Stop(runCtx); err != nil {
			return fmt.Errorf("failed stop river client: %w", err)
		}
		return nil
	})
}
