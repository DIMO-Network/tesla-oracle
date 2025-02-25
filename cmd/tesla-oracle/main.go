package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/middleware"
	"github.com/DIMO-Network/tesla-oracle/internal/rpc"
	grpc_oracle "github.com/DIMO-Network/tesla-oracle/pkg/grpc"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"google.golang.org/grpc"

	"github.com/DIMO-Network/shared"
	"github.com/DIMO-Network/shared/db"
	"github.com/rs/zerolog"
)

func main() {
	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "tesla-oracle").
		Logger()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

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

	pdb := db.NewDbConnectionFromSettings(ctx, &settings.DB, true)
	pdb.WaitForDB(logger)

	teslaSvc := rpc.NewTeslaRPCService(pdb.DBS, &settings, &logger)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", settings.GRPCPort))
	if err != nil {
		logger.Fatal().Err(err).Msgf("Couldn't listen on gRPC port %d", settings.GRPCPort)
	}

	logger.Info().Msgf("Starting gRPC server on port %d", settings.GRPCPort)

	mdw := middleware.New(&logger)
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

	go func() {
		if err := server.Serve(lis); err != nil {
			logger.Fatal().Err(err).Msg("gRPC server terminated unexpectedly")
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	logger.Info().Msg("Gracefully shutting down and running cleanup tasks...")
	_ = ctx.Done()
	_ = pdb.DBS().Writer.Close()
	_ = pdb.DBS().Reader.Close()

}
