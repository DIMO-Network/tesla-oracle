package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/DIMO-Network/shared/pkg/settings"
	"github.com/DIMO-Network/tesla-oracle/internal/bootstrap"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

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

	level, err := zerolog.ParseLevel(settings.LogLevel)
	if err != nil {
		logger.Fatal().Err(err).Msgf("could not parse LOG_LEVEL: %s", settings.LogLevel)
	}
	zerolog.SetGlobalLevel(level)

	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		handleMigration(&logger, &settings)
		return
	}

	// Initialize all services
	services, err := bootstrap.InitializeServices(ctx, &logger, &settings)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize services")
	}
	defer services.Cleanup()

	group, gCtx := errgroup.WithContext(ctx)

	// Start River workers
	runRiver(gCtx, logger, services.RiverClient, group)

	// Initialize and start servers
	serverManager := bootstrap.NewServerManager(&settings, &logger, services)
	if err := serverManager.Initialize(); err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize servers")
	}
	serverManager.StartAll(gCtx, group)

	// Start consumers
	consumerManager := bootstrap.NewConsumerManager(&settings, &logger, services)
	if err := consumerManager.StartConsumers(gCtx, group); err != nil {
		logger.Fatal().Err(err).Msg("failed to start consumers")
	}

	// Wait for shutdown
	if err := group.Wait(); err != nil {
		logger.Fatal().Err(err).Msg("Server error on shutdown.")
	}

	logger.Info().Msg("Gracefully shutting down and running cleanup tasks...")
}

// handleMigration handles database migration commands
func handleMigration(logger *zerolog.Logger, settings *config.Settings) {
	command := "up"
	if len(os.Args) > 2 {
		command = os.Args[2]
		if command == "down-to" || command == "up-to" {
			command = command + " " + os.Args[3]
		}
	}
	logger.Info().Msg("Starting migration")
	migrateDatabase(*logger, settings, command)
	logger.Info().Msg("Migration complete")
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
