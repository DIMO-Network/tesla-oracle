package main

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
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

	t.Run("Verify River Migration Versions", func(t *testing.T) {
		verifyRiverMigrationVersions(t, dbConn)
	})

	t.Run("Verify River Client Tables Dropped", func(t *testing.T) {
		verifyRiverClientTablesDropped(t, dbConn)
	})

	t.Run("Verify River Notification Table", func(t *testing.T) {
		verifyRiverNotificationTable(t, dbConn)
	})

	t.Run("Verify River Column Defaults", func(t *testing.T) {
		verifyRiverColumnDefaults(t, dbConn)
	})

	t.Run("Verify River Functions", func(t *testing.T) {
		verifyRiverFunctions(t, dbConn)
	})

	t.Run("Verify River Indexes", func(t *testing.T) {
		verifyRiverIndexes(t, dbConn)
	})
}

// TestRiverUpgradeWithJobsInFlight starts from the schema River v0.23.1 left in
// production (version 6) with jobs in every state a deploy can find them in, and
// runs the same migrate step the init container runs. No job may be touched, and
// a job queued before the upgrade must still be worked after it. It then takes the
// rollback path down to version 6 and back up.
func TestRiverUpgradeWithJobsInFlight(t *testing.T) {
	ctx := context.Background()

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

	dbConn, err := sql.Open("postgres", settings.DB.BuildConnectionString(true))
	require.NoError(t, err)
	defer func() {
		if err := dbConn.Close(); err != nil {
			t.Logf("failed to close db: %s", err)
		}
	}()
	_, err = dbConn.Exec("CREATE SCHEMA IF NOT EXISTS tesla_oracle;")
	require.NoError(t, err)

	migrator, err := rivermigrate.New(riverdatabasesql.New(dbConn), &rivermigrate.Config{Schema: "tesla_oracle"})
	require.NoError(t, err)

	_, err = migrator.Migrate(ctx, rivermigrate.DirectionUp, &rivermigrate.MigrateOpts{TargetVersion: riverVersionBeforeUpgrade})
	require.NoError(t, err)
	requireRiverVersions(t, dbConn, 1, 2, 3, 4, 5, 6)
	requireTableExists(t, dbConn, "river_client", true)
	requireTableExists(t, dbConn, "river_client_queue", true)

	// Written as v0.23.1 wrote them, with max_attempts given explicitly: the column
	// has no default at version 6.
	queued := insertRiverJob(t, dbConn, "available", "default", upgradeProbeArgs{}.Kind(), `{"id": 1}`)
	inFlight := map[string]int64{
		"running":   insertRiverJob(t, dbConn, "running", "tesla_commands", "tesla_command", `{"vin": "running"}`),
		"retryable": insertRiverJob(t, dbConn, "retryable", "tesla_commands", "tesla_command", `{"vin": "retryable"}`),
		"scheduled": insertRiverJob(t, dbConn, "scheduled", "tesla_polls", "tesla_legacy_poll", `{"vin": "scheduled"}`),
	}
	before := riverJobSnapshot(t, dbConn)

	logger := zerolog.New(os.Stdout).Level(zerolog.DebugLevel)
	migrateDatabase(logger, settings, "up")

	requireRiverVersions(t, dbConn, 1, 2, 3, 4, 5, 6, 7, 8)
	require.Equal(t, before, riverJobSnapshot(t, dbConn), "migrating must not change queued or in-flight jobs")
	verifyRiverClientTablesDropped(t, dbConn)
	verifyRiverNotificationTable(t, dbConn)

	// The up migration is safe to repeat: a failed rollout re-runs the init container.
	migrateDatabase(logger, settings, "up")
	requireRiverVersions(t, dbConn, 1, 2, 3, 4, 5, 6, 7, 8)

	// A job queued by the old version is worked by the new client. The rows above
	// have no registered worker here, and their queues aren't configured.
	pool, err := pgxpool.New(ctx, settings.DB.BuildConnectionString(true))
	require.NoError(t, err)
	defer pool.Close()

	worked := make(chan int64, 1)
	workers := river.NewWorkers()
	river.AddWorker(workers, river.WorkFunc(func(_ context.Context, job *river.Job[upgradeProbeArgs]) error {
		worked <- job.ID
		return nil
	}))
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:  map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 1}},
		Workers: workers,
	})
	require.NoError(t, err)
	require.NoError(t, client.Start(ctx))
	defer func() {
		if err := client.Stop(ctx); err != nil {
			t.Logf("failed to stop river client: %s", err)
		}
	}()

	select {
	case id := <-worked:
		require.Equal(t, queued, id)
	case <-time.After(30 * time.Second):
		require.Fail(t, "job queued before the upgrade was not worked after it")
	}

	// The rollback path: back to version 6 with the jobs still there, then forward.
	_, err = migrator.Migrate(ctx, rivermigrate.DirectionDown, &rivermigrate.MigrateOpts{TargetVersion: riverVersionBeforeUpgrade})
	require.NoError(t, err)
	requireRiverVersions(t, dbConn, 1, 2, 3, 4, 5, 6)
	requireTableExists(t, dbConn, "river_client", true)
	requireTableExists(t, dbConn, "river_client_queue", true)
	requireTableExists(t, dbConn, "river_notification", false)
	for state, id := range inFlight {
		var got string
		require.NoError(t, dbConn.QueryRow(`SELECT state::text FROM tesla_oracle.river_job WHERE id = $1`, id).Scan(&got))
		require.Equal(t, state, got, "migrating down must not change jobs")
	}

	migrateDatabase(logger, settings, "up")
	requireRiverVersions(t, dbConn, 1, 2, 3, 4, 5, 6, 7, 8)
}

// riverVersionBeforeUpgrade is the newest schema River v0.23.1 knows about.
const riverVersionBeforeUpgrade = 6

// upgradeProbeArgs is a job kind only TestRiverUpgradeWithJobsInFlight registers.
type upgradeProbeArgs struct {
	ID int `json:"id"`
}

func (upgradeProbeArgs) Kind() string { return "river_upgrade_probe" }

func insertRiverJob(t *testing.T, db *sql.DB, state, queue, kind, args string) int64 {
	t.Helper()

	var attemptedAt, attemptedBy any
	attempt := 0
	if state == "running" || state == "retryable" {
		attempt = 1
		attemptedAt = time.Now()
		attemptedBy = `{old-pod}`
	}
	scheduledAt := time.Now()
	if state == "scheduled" || state == "retryable" {
		scheduledAt = scheduledAt.Add(time.Hour)
	}

	var id int64
	err := db.QueryRow(`
		INSERT INTO tesla_oracle.river_job (args, attempt, attempted_at, attempted_by, kind, max_attempts, priority, queue, scheduled_at, state)
		VALUES ($1, $2, $3, $4, $5, 25, 1, $6, $7, $8::tesla_oracle.river_job_state)
		RETURNING id
	`, args, attempt, attemptedAt, attemptedBy, kind, queue, scheduledAt, state).Scan(&id)
	require.NoError(t, err)
	return id
}

// riverJobSnapshot returns every river_job row as text, so a test can tell whether
// any column of any job changed.
func riverJobSnapshot(t *testing.T, db *sql.DB) []string {
	t.Helper()

	rows, err := db.Query(`SELECT j::text FROM tesla_oracle.river_job j ORDER BY id`)
	require.NoError(t, err)
	defer func() {
		if err := rows.Close(); err != nil {
			t.Logf("failed to close rows: %s", err)
		}
	}()

	var snapshot []string
	for rows.Next() {
		var row string
		require.NoError(t, rows.Scan(&row))
		snapshot = append(snapshot, row)
	}
	require.NoError(t, rows.Err())
	return snapshot
}

func requireRiverVersions(t *testing.T, db *sql.DB, expected ...int) {
	t.Helper()

	rows, err := db.Query(`SELECT version FROM tesla_oracle.river_migration WHERE line = 'main' ORDER BY version`)
	require.NoError(t, err)
	defer func() {
		if err := rows.Close(); err != nil {
			t.Logf("failed to close rows: %s", err)
		}
	}()

	var versions []int
	for rows.Next() {
		var version int
		require.NoError(t, rows.Scan(&version))
		versions = append(versions, version)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, expected, versions)
}

func requireTableExists(t *testing.T, db *sql.DB, table string, expected bool) {
	t.Helper()

	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_schema = 'tesla_oracle'
			AND table_name = $1
		)
	`, table).Scan(&exists)
	require.NoError(t, err)
	require.Equal(t, expected, exists, "table %s existence", table)
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

func verifyRiverMigrationVersions(t *testing.T, db *sql.DB) {
	requireRiverVersions(t, db, 1, 2, 3, 4, 5, 6, 7, 8)
}

// verifyRiverClientTablesDropped checks migration 7 removed the two tables River
// created but never used.
func verifyRiverClientTablesDropped(t *testing.T, db *sql.DB) {
	requireTableExists(t, db, "river_client", false)
	requireTableExists(t, db, "river_client_queue", false)
}

// verifyRiverNotificationTable checks the table migration 7 adds on Postgres too,
// although River's changelog lists it as SQLite only.
func verifyRiverNotificationTable(t *testing.T, db *sql.DB) {
	requireTableExists(t, db, "river_notification", true)

	expectedIndexes := []string{"river_notification_created_at_idx", "river_notification_topic_id_idx"}
	for _, indexName := range expectedIndexes {
		var exists bool
		err := db.QueryRow(`
			SELECT EXISTS (
				SELECT FROM pg_indexes
				WHERE schemaname = 'tesla_oracle'
				AND tablename = 'river_notification'
				AND indexname = $1
			)
		`, indexName).Scan(&exists)
		require.NoError(t, err)
		require.True(t, exists, "Index %s should exist on river_notification table", indexName)
	}
}

// verifyRiverColumnDefaults checks the two defaults migration 7 adds. v0.23.1
// always writes both columns, so a pod still running it doesn't notice them.
func verifyRiverColumnDefaults(t *testing.T, db *sql.DB) {
	expectedDefaults := map[string]string{
		"river_job.max_attempts": "25",
		"river_queue.updated_at": "CURRENT_TIMESTAMP",
	}
	for column, expected := range expectedDefaults {
		table, name, _ := strings.Cut(column, ".")
		var columnDefault sql.NullString
		err := db.QueryRow(`
			SELECT column_default
			FROM information_schema.columns
			WHERE table_schema = 'tesla_oracle'
			AND table_name = $1
			AND column_name = $2
		`, table, name).Scan(&columnDefault)
		require.NoError(t, err)
		require.Equal(t, expected, columnDefault.String, "Default of %s", column)
	}
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
