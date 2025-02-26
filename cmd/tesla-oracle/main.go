package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/middleware"
	"github.com/DIMO-Network/tesla-oracle/internal/rpc"
	"github.com/DIMO-Network/tesla-oracle/internal/services"
	grpc_oracle "github.com/DIMO-Network/tesla-oracle/pkg/grpc"
	"github.com/IBM/sarama"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/DIMO-Network/shared"
	"github.com/DIMO-Network/shared/db"
	"github.com/rs/zerolog"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "tesla-oracle").
		Logger()

	settings, err := shared.LoadConfig[config.Settings]("settings.yaml")
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

	mdw := middleware.New(&logger)

	pdb := db.NewDbConnectionFromSettings(ctx, &settings.DB, true)
	pdb.WaitForDB(logger)

	teslaSvc := rpc.NewTeslaRPCService(pdb.DBS, &settings, &logger)
	server := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			mdw.MetricsMiddleware(),
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_prometheus.UnaryServerInterceptor,
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(mdw.PanicMiddleware())),
		)),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	)

	grpc_oracle.RegisterTeslaOracleServer(server, teslaSvc)

	config := sarama.NewConfig()
	config.Version = sarama.V3_6_0_0

	brokers := strings.Split(settings.KafkaBrokers, ",")
	kClient, err := sarama.NewClient(brokers, config)
	if err != nil {
		logger.Fatal().Err(err).Msg("error creating kafka client")
	}

	logger.Info().Msgf("Starting gRPC server on port %d", settings.GRPCPort)

	consumer, err := sarama.NewConsumerGroupFromClient(settings.TopicContractEvent, kClient)
	if err != nil {
		logger.Fatal().Err(err).Msg("error creating consumer from client")
	}

	proc := services.NewProcessor(pdb, &logger)

	group, gCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		if err := StartContractEventConsumer(gCtx, proc, consumer, settings.TopicContractEvent, &logger); err != nil {
			logger.Fatal().Err(err).Msg("error starting contract event consumer")
			return err
		}

		return nil
	})

	group.Go(func() error {
		if err := StartGRPCServer(server, settings.GRPCPort, &logger); err != nil {
			return err
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
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		logger.Fatal().Err(err).Msgf("Couldn't listen on gRPC port %d", grpcPort)
	}

	if err := server.Serve(lis); err != nil {
		logger.Fatal().Err(err).Msg("gRPC server terminated unexpectedly")
	}

	return nil
}

func StartContractEventConsumer(ctx context.Context, proc *services.Processor, consumer sarama.ConsumerGroup, topic string, logger *zerolog.Logger) error {
	for {
		logger.Info().Msgf("starting consumer: %s", topic)
		if err := consumer.Consume(ctx, strings.Split(topic, ","), proc); err != nil {
			if errors.Is(err, sarama.ErrClosedConsumerGroup) {
				return nil
			}
			logger.Err(err).Msg("consumer failure")
			return err
		}
		if ctx.Err() != nil { // returning nil since this can only be context cancelled
			return nil
		}
	}
}
