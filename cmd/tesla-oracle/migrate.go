package main

import (
	"context"
	"database/sql"
	"tesla-oracle/internal/config"
	"tesla-oracle/migrations"

	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog"
)

func migrateDatabase(logger zerolog.Logger, settings *config.Settings, command string) {
	var db *sql.DB
	// setup database
	db, err := sql.Open("postgres", settings.DB.BuildConnectionString(true))
	defer func() {
		if err := db.Close(); err != nil {
			logger.Fatal().Msgf("goose: failed to close DB: %v\n", err)
		}
	}()
	if err != nil {
		logger.Fatal().Msgf("failed to open db connection: %v\n", err)
	}
	if err = db.Ping(); err != nil {
		logger.Fatal().Msgf("failed to ping db: %v\n", err)
	}
	// set default
	if command == "" {
		command = "up"
	}

	_, err = db.Exec("CREATE SCHEMA IF NOT EXISTS tesla_oracle;")
	if err != nil {
		logger.Fatal().Err(err).Msg("could not create schema")
	}
	goose.SetTableName("tesla_oracle.migrations")
	goose.SetBaseFS(migrations.FileOS)
	// print dirs in migrations
	if err := goose.RunContext(context.Background(), command, db, "."); err != nil {
		logger.Fatal().Msgf("failed to apply go code migrations: %v\n", err)
	}

}
