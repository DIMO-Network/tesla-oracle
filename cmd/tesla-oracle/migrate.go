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

// migrationLockTimeout is how long a migration waits for a table lock, in
// milliseconds. Postgres queues every later query on the table behind a waiting
// ALTER TABLE, so without a limit one long transaction stops all job traffic. On
// timeout the migration rolls back and the init container retries.
const migrationLockTimeout = 5000

func migrateDatabase(logger zerolog.Logger, settings *config.Settings, command string) error {
	var db *sql.DB
	// setup database
	dsn := fmt.Sprintf("%s lock_timeout=%d", settings.DB.BuildConnectionString(true), migrationLockTimeout)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to open db connection: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error().Err(err).Msg("goose: failed to close DB")
		}
	}()
	if err = db.Ping(); err != nil {
		return fmt.Errorf("failed to ping db: %w", err)
	}
	// set default
	if command == "" {
		command = "up"
	}

	_, err = db.Exec("CREATE SCHEMA IF NOT EXISTS tesla_oracle;")
	if err != nil {
		return fmt.Errorf("could not create schema: %w", err)
	}

	if err := migrateRiver(context.Background(), db); err != nil {
		return fmt.Errorf("failed to migrate river: %w", err)
	}

	goose.SetTableName("tesla_oracle.migrations")
	goose.SetBaseFS(migrations.FileOS)
	// print dirs in migrations
	if err := goose.RunContext(context.Background(), command, db, "."); err != nil {
		return fmt.Errorf("failed to apply go code migrations: %w", err)
	}

	return nil
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
