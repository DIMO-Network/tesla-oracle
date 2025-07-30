package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/migrations"
	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivermigrate"
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

	if err := migrateRiver(context.Background(), db); err != nil {
		logger.Fatal().Err(err).Msg("failed to migrate river")
	}

	goose.SetTableName("tesla_oracle.migrations")
	goose.SetBaseFS(migrations.FileOS)
	// print dirs in migrations
	if err := goose.RunContext(context.Background(), command, db, "."); err != nil {
		logger.Fatal().Msgf("failed to apply go code migrations: %v\n", err)
	}

}

func migrateRiver(ctx context.Context, db *sql.DB) error {
	driver := riverdatabasesql.New(db)
	migrator, err := rivermigrate.New(driver, &rivermigrate.Config{
		Schema: "tesla_oracle",
	})
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	res, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	if err != nil {
		return fmt.Errorf("failed to migrate: %w", err)
	}
	for _, version := range res.Versions {
		fmt.Printf("Migrated [%s] version %d\n", strings.ToUpper(string(res.Direction)), version.Version)
	}

	return nil
}
