package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"tesla-oracle/internal/config"
	"tesla-oracle/internal/services"

	"github.com/DIMO-Network/shared"
	"github.com/DIMO-Network/shared/db"
	"github.com/IBM/sarama"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
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

	config := sarama.NewConfig()
	config.Version = sarama.V3_6_0_0

	brokers := strings.Split(settings.KafkaBrokers, ",")
	kClient, err := sarama.NewClient(brokers, config)
	if err != nil {
		logger.Fatal().Err(err).Msg("error creating kafka client")
	}

	consumer, err := sarama.NewConsumerGroupFromClient(settings.TopicContractEvent, kClient)
	if err != nil {
		logger.Fatal().Err(err).Msg("error creating consumer from client")
	}

	proc := services.NewProcessor("", 4, &logger)

	group, gCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		for {
			logger.Info().Msgf("starting consumer: %s", settings.TopicContractEvent)
			if err := consumer.Consume(gCtx, strings.Split(settings.TopicContractEvent, ","), proc); err != nil {
				if errors.Is(err, sarama.ErrClosedConsumerGroup) {
					return nil
				}
				logger.Err(err).Msg("consumer failure")
				return err
			}
			if gCtx.Err() != nil { // returning nil since this can only be context cancelled
				return nil
			}
		}
	})

}
