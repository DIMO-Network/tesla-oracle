package main

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

const dbName = "tesla_oracle"

func TestRiverMigrations(t *testing.T) {
	ctx := context.Background()

	// Setup test container
	container, err := postgres.Run(ctx,
		"postgres:15",
		postgres.WithDatabase(dbName),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		postgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	defer func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}()

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	settings := &config.Settings{
		DB: db.Settings{
			Host:     host,
			Port:     port.Port(),
			User:     "postgres",
			Password: "postgres",
			Name:     dbName,
			SSLMode:  "disable",
		},
	}

	// Run migrations
	logger := zerolog.New(os.Stdout).Level(zerolog.DebugLevel)
	migrateDatabase(logger, settings, "up")
	// Connect to database
	dbConn, err := sql.Open("postgres", settings.DB.BuildConnectionString(true))
	require.NoError(t, err)
	defer func() {
		if err := dbConn.Close(); err != nil {
			t.Logf("failed to close rows: %s", err)
		}
	}()

	// Verify all River tables and structures are created
	t.Run("Verify River Enum Types", func(t *testing.T) {
		verifyRiverEnumTypes(t, dbConn)
	})
	t.Run("Verify River Job Table", func(t *testing.T) {
		verifyRiverJobTable(t, dbConn)
	})

	t.Run("Verify River Leader Table", func(t *testing.T) {
		verifyRiverLeaderTable(t, dbConn)
	})
	t.Run("Verify River Queue Table", func(t *testing.T) {
		verifyRiverQueueTable(t, dbConn)
	})

	t.Run("Verify River Client Tables", func(t *testing.T) {
		verifyRiverClientTables(t, dbConn)
	})

	t.Run("Verify River Functions", func(t *testing.T) {
		verifyRiverFunctions(t, dbConn)
	})

	t.Run("Verify River Indexes", func(t *testing.T) {
		verifyRiverIndexes(t, dbConn)
	})
}

func verifyRiverEnumTypes(t *testing.T, db *sql.DB) {
	// Verify river_job_state enum exists and has expected values
	var enumValues []string
	rows, err := db.Query(`
		SELECT unnest(enum_range(NULL::river_job_state))::text 
		ORDER BY unnest(enum_range(NULL::river_job_state))::text
	`)
	require.NoError(t, err)
	defer func() {
		if err := rows.Close(); err != nil {
			t.Logf("failed to close rows: %s", err)
		}
	}()

	for rows.Next() {
		var value string
		err := rows.Scan(&value)
		require.NoError(t, err)
		enumValues = append(enumValues, value)
	}

	expectedValues := []string{
		"available", "cancelled", "completed", "discarded",
		"pending", "retryable", "running", "scheduled",
	}
	require.ElementsMatch(t, expectedValues, enumValues, "river_job_state enum should have all expected values")
}

func verifyRiverJobTable(t *testing.T, db *sql.DB) {
	// Verify table exists
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'tesla_oracle' 
			AND table_name = 'river_job'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, "river_job table should exist")

	// Verify key columns exist with correct types
	expectedColumns := map[string]string{
		"id":            "bigint",
		"state":         "river_job_state",
		"attempt":       "smallint",
		"max_attempts":  "smallint",
		"attempted_at":  "timestamp with time zone",
		"created_at":    "timestamp with time zone",
		"finalized_at":  "timestamp with time zone",
		"scheduled_at":  "timestamp with time zone",
		"priority":      "smallint",
		"args":          "jsonb",
		"attempted_by":  "text[]",
		"errors":        "jsonb[]",
		"kind":          "text",
		"metadata":      "jsonb",
		"queue":         "text",
		"tags":          "character varying[]",
		"unique_key":    "bytea",
		"unique_states": "bit",
	}

	for columnName, expectedType := range expectedColumns {
		var dataType string
		err := db.QueryRow(`
			SELECT data_type 
			FROM information_schema.columns 
			WHERE table_schema = 'tesla_oracle' 
			AND table_name = 'river_job' 
			AND column_name = $1
		`, columnName).Scan(&dataType)
		require.NoError(t, err, "Column %s should exist", columnName)

		// Handle special cases for type matching
		if columnName == "state" {
			require.Equal(t, "USER-DEFINED", dataType, "Column %s should be USER-DEFINED type (enum)", columnName)
		} else if columnName == "unique_states" {
			require.Equal(t, "bit", dataType, "Column %s should be bit type", columnName)
		} else if expectedType == "text[]" || expectedType == "jsonb[]" || expectedType == "character varying[]" {
			require.Equal(t, "ARRAY", dataType, "Column %s should be ARRAY type", columnName)
		} else if expectedType == "timestamp with time zone" {
			require.Equal(t, "timestamp with time zone", dataType, "Column %s should be timestamp with time zone", columnName)
		} else {
			require.Contains(t, []string{expectedType, strings.ToUpper(expectedType)}, dataType,
				"Column %s should have type %s, got %s", columnName, expectedType, dataType)
		}
	}

	// Verify constraints exist
	constraintNames := []string{
		"finalized_or_finalized_at_null",
		"max_attempts_is_positive",
		"priority_in_range",
		"queue_length",
		"kind_length",
	}

	for _, constraintName := range constraintNames {
		var exists bool
		err := db.QueryRow(`
			SELECT EXISTS (
				SELECT FROM information_schema.table_constraints 
				WHERE table_schema = 'tesla_oracle' 
				AND table_name = 'river_job'
				AND constraint_name = $1
			)
		`, constraintName).Scan(&exists)
		require.NoError(t, err)
		require.True(t, exists, "Constraint %s should exist on river_job table", constraintName)
	}
}

func verifyRiverLeaderTable(t *testing.T, db *sql.DB) {
	// Verify table exists
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'tesla_oracle' 
			AND table_name = 'river_leader'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, "river_leader table should exist")

	// Verify key columns
	expectedColumns := []string{
		"elected_at", "expires_at", "leader_id", "name",
	}

	for _, columnName := range expectedColumns {
		var exists bool
		err := db.QueryRow(`
			SELECT EXISTS (
				SELECT FROM information_schema.columns 
				WHERE table_schema = 'tesla_oracle' 
				AND table_name = 'river_leader' 
				AND column_name = $1
			)
		`, columnName).Scan(&exists)
		require.NoError(t, err)
		require.True(t, exists, "Column %s should exist in river_leader table", columnName)
	}
}

func verifyRiverQueueTable(t *testing.T, db *sql.DB) {
	// Verify table exists
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'tesla_oracle' 
			AND table_name = 'river_queue'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, "river_queue table should exist")

	// Verify key columns
	expectedColumns := []string{
		"name", "created_at", "metadata", "paused_at", "updated_at",
	}

	for _, columnName := range expectedColumns {
		var exists bool
		err := db.QueryRow(`
			SELECT EXISTS (
				SELECT FROM information_schema.columns 
				WHERE table_schema = 'tesla_oracle' 
				AND table_name = 'river_queue' 
				AND column_name = $1
			)
		`, columnName).Scan(&exists)
		require.NoError(t, err)
		require.True(t, exists, "Column %s should exist in river_queue table", columnName)
	}
}

func verifyRiverClientTables(t *testing.T, db *sql.DB) {
	// Verify river_client table exists
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'tesla_oracle' 
			AND table_name = 'river_client'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, "river_client table should exist")

	// Verify river_client_queue table exists
	err = db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables 
			WHERE table_schema = 'tesla_oracle' 
			AND table_name = 'river_client_queue'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, "river_client_queue table should exist")

	// Verify river_client_queue has foreign key to river_client
	err = db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage kcu 
				ON tc.constraint_name = kcu.constraint_name
			WHERE tc.table_schema = 'tesla_oracle'
			AND tc.table_name = 'river_client_queue'
			AND tc.constraint_type = 'FOREIGN KEY'
			AND kcu.column_name = 'river_client_id'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, "river_client_queue should have foreign key to river_client")
}

func verifyRiverFunctions(t *testing.T, db *sql.DB) {
	// Verify river_job_state_in_bitmask function exists
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.routines 
			WHERE routine_schema = 'tesla_oracle' 
			AND routine_name = 'river_job_state_in_bitmask'
			AND routine_type = 'FUNCTION'
		)
	`).Scan(&exists)
	require.NoError(t, err)
	require.True(t, exists, "river_job_state_in_bitmask function should exist")

	// Test the function works
	var result bool
	err = db.QueryRow(`SELECT river_job_state_in_bitmask(B'00000001', 'available')`).Scan(&result)
	require.NoError(t, err)
	require.True(t, result, "river_job_state_in_bitmask should return true for available state with correct bitmask")
}

func verifyRiverIndexes(t *testing.T, db *sql.DB) {
	expectedIndexes := []string{
		"river_job_kind",
		"river_job_state_and_finalized_at_index",
		"river_job_prioritized_fetching_index",
		"river_job_args_index",
		"river_job_metadata_index",
		"river_job_unique_idx",
	}

	for _, indexName := range expectedIndexes {
		var exists bool
		err := db.QueryRow(`
			SELECT EXISTS (
				SELECT FROM pg_indexes 
				WHERE schemaname = 'tesla_oracle' 
				AND tablename = 'river_job'
				AND indexname = $1
			)
		`, indexName).Scan(&exists)
		require.NoError(t, err)
		require.True(t, exists, "Index %s should exist on river_job table", indexName)
	}
}
