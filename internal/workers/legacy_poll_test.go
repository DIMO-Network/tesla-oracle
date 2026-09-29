package workers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/test"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testVehicleTokenID = 170722
	testVIN            = "5YJSA1E26HF000001"
	testPollInterval   = 5 * time.Minute
)

// fakeVehicleRepo implements the two repository calls the poll worker makes.
type fakeVehicleRepo struct {
	repository.VehicleRepository
	device      *dbmodels.SyntheticDevice
	getErr      error
	updateErr   error
	savedStatus string
}

func (f *fakeVehicleRepo) GetSyntheticDeviceByTokenID(context.Context, int64) (*dbmodels.SyntheticDevice, error) {
	return f.device, f.getErr
}

func (f *fakeVehicleRepo) UpdateSyntheticDeviceSubscriptionStatus(_ context.Context, device *dbmodels.SyntheticDevice, status string) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.savedStatus = status
	device.SubscriptionStatus = null.StringFrom(status)
	return nil
}

func activeDevice(t *testing.T, cip cipher.Cipher) *dbmodels.SyntheticDevice {
	access, err := cip.Encrypt("access-token")
	require.NoError(t, err)
	refresh, err := cip.Encrypt("refresh-token")
	require.NoError(t, err)
	return &dbmodels.SyntheticDevice{
		Vin:                testVIN,
		VehicleTokenID:     null.IntFrom(testVehicleTokenID),
		AccessToken:        null.StringFrom(access),
		RefreshToken:       null.StringFrom(refresh),
		AccessExpiresAt:    null.TimeFrom(time.Now().Add(time.Hour)),
		RefreshExpiresAt:   null.TimeFrom(time.Now().Add(24 * time.Hour)),
		SubscriptionStatus: null.StringFrom("active"),
	}
}

func newTestWorker(pool *pgxpool.Pool, repo *fakeVehicleRepo, fleetAPI *test.MockTeslaFleetAPIService) *LegacyTeslaPollWorker {
	logger := zerolog.Nop()
	tokenManager := core.NewTeslaTokenManager(new(cipher.ROT13Cipher), repo, fleetAPI, &logger)
	// A sender with no DIS client fails on devices without token metadata.
	sender := NewLegacyPollSender(nil, nil, common.Address{}, common.Address{}, "", 0, &logger)
	return NewLegacyTeslaPollWorker(pool, fleetAPI, tokenManager, repo, sender, &logger, testPollInterval)
}

type pollJob struct {
	state       string
	scheduledAt time.Time
}

func pollJobs(t *testing.T, pool *pgxpool.Pool) []pollJob {
	rows, err := pool.Query(context.Background(),
		"SELECT state::text, scheduled_at FROM river_job WHERE kind = $1 ORDER BY id", LegacyTeslaPollArgs{}.Kind())
	require.NoError(t, err)
	defer rows.Close()

	var jobs []pollJob
	for rows.Next() {
		var job pollJob
		require.NoError(t, rows.Scan(&job.state, &job.scheduledAt))
		jobs = append(jobs, job)
	}
	require.NoError(t, rows.Err())
	return jobs
}

// TestLegacyPollJobs runs the scheduler and the worker against a real River
// client and Postgres, so River's own insert validation, unique handling and
// job completion behave as in prod.
func TestLegacyPollJobs(t *testing.T) {
	ctx := context.Background()
	pdb, container, settings := test.StartContainerDatabase(ctx, t, "../../migrations")
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	migrator, err := rivermigrate.New(riverdatabasesql.New(pdb.DBS().Writer.DB), &rivermigrate.Config{Schema: "tesla_oracle"})
	require.NoError(t, err)
	_, err = migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	require.NoError(t, err)

	pool, err := pgxpool.New(ctx, settings.DB.BuildConnectionString(true))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	logger := zerolog.Nop()
	cip := new(cipher.ROT13Cipher)

	// startClient runs the worker on a started River client until the test ends.
	startClient := func(t *testing.T, worker *LegacyTeslaPollWorker) *river.Client[pgx.Tx] {
		workers := river.NewWorkers()
		river.AddWorker(workers, worker)
		client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
			Queues:            map[string]river.QueueConfig{"tesla_polls": {MaxWorkers: 1}},
			Workers:           workers,
			FetchCooldown:     10 * time.Millisecond,
			FetchPollInterval: 50 * time.Millisecond,
			Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
			TestOnly:          true,
		})
		require.NoError(t, err)
		require.NoError(t, client.Start(ctx))
		t.Cleanup(func() { require.NoError(t, client.Stop(ctx)) })
		return client
	}

	resetJobs := func(t *testing.T) {
		_, err := pool.Exec(ctx, "DELETE FROM river_job")
		require.NoError(t, err)
	}

	// waitFor waits until the worker has taken the first job out of the queue.
	waitFor := func(t *testing.T, done func(jobs []pollJob) bool) []pollJob {
		var jobs []pollJob
		require.Eventually(t, func() bool {
			jobs = pollJobs(t, pool)
			return done(jobs)
		}, 30*time.Second, 50*time.Millisecond)
		return jobs
	}

	t.Run("schedules one poll per vehicle", func(t *testing.T) {
		resetJobs(t)
		client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
		require.NoError(t, err)
		scheduler := NewLegacyTeslaPollScheduler(client, &logger)
		device := &dbmodels.SyntheticDevice{VehicleTokenID: null.IntFrom(testVehicleTokenID), Vin: testVIN}

		require.NoError(t, scheduler.ScheduleLegacyPoll(ctx, device))
		// Starting data flow again (a reconnect) must not add a second poll loop.
		require.NoError(t, scheduler.ScheduleLegacyPoll(ctx, device))

		require.Len(t, pollJobs(t, pool), 1)
	})

	t.Run("each poll schedules the next one before calling Tesla", func(t *testing.T) {
		resetJobs(t)
		repo := &fakeVehicleRepo{device: activeDevice(t, cip)}
		fleetAPI := new(test.MockTeslaFleetAPIService)
		fleetAPI.On("GetLegacyVehicleData", mock.Anything, "access-token", testVIN).Return(nil, errors.New("tesla 503"))
		client := startClient(t, newTestWorker(pool, repo, fleetAPI))
		scheduler := NewLegacyTeslaPollScheduler(client, &logger)

		started := time.Now()
		require.NoError(t, scheduler.ScheduleLegacyPoll(ctx, repo.device))
		jobs := waitFor(t, func(jobs []pollJob) bool { return len(jobs) == 2 })

		require.Equal(t, "completed", jobs[0].state)
		require.Equal(t, "scheduled", jobs[1].state)
		require.WithinDuration(t, started.Add(testPollInterval), jobs[1].scheduledAt, time.Minute)
		require.Eventually(t, func() bool { return len(fleetAPI.Calls) == 1 }, 10*time.Second, 50*time.Millisecond)

		// /start while the next poll is waiting adds nothing.
		require.NoError(t, scheduler.ScheduleLegacyPoll(ctx, repo.device))
		require.Len(t, pollJobs(t, pool), 2)
	})

	t.Run("stops when the device is no longer active", func(t *testing.T) {
		resetJobs(t)
		device := activeDevice(t, cip)
		device.SubscriptionStatus = null.StringFrom("pending")
		fleetAPI := new(test.MockTeslaFleetAPIService)
		client := startClient(t, newTestWorker(pool, &fakeVehicleRepo{device: device}, fleetAPI))

		require.NoError(t, NewLegacyTeslaPollScheduler(client, &logger).ScheduleLegacyPoll(ctx, device))
		jobs := waitFor(t, func(jobs []pollJob) bool { return len(jobs) == 1 && jobs[0].state == "completed" })

		require.Len(t, jobs, 1)
		fleetAPI.AssertNotCalled(t, "GetLegacyVehicleData", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("retries at the poll interval when the device can't be loaded", func(t *testing.T) {
		resetJobs(t)
		repo := &fakeVehicleRepo{getErr: errors.New("connection reset")}
		client := startClient(t, newTestWorker(pool, repo, new(test.MockTeslaFleetAPIService)))

		started := time.Now()
		device := &dbmodels.SyntheticDevice{VehicleTokenID: null.IntFrom(testVehicleTokenID), Vin: testVIN}
		require.NoError(t, NewLegacyTeslaPollScheduler(client, &logger).ScheduleLegacyPoll(ctx, device))
		jobs := waitFor(t, func(jobs []pollJob) bool { return len(jobs) == 1 && jobs[0].state == "retryable" })

		require.WithinDuration(t, started.Add(testPollInterval), jobs[0].scheduledAt, time.Minute)
	})
}

func TestLegacyTeslaPollWorkerPoll(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.Nop()
	cip := new(cipher.ROT13Cipher)

	t.Run("marks the vehicle pending when Tesla rejects the token", func(t *testing.T) {
		repo := &fakeVehicleRepo{device: activeDevice(t, cip)}
		fleetAPI := new(test.MockTeslaFleetAPIService)
		fleetAPI.On("GetLegacyVehicleData", mock.Anything, "access-token", testVIN).Return(nil, core.ErrFleetAPIUnauthorized)

		newTestWorker(nil, repo, fleetAPI).poll(ctx, &logger, repo.device)
		require.Equal(t, "pending", repo.savedStatus)
		require.False(t, shouldContinueLegacyPolling(repo.device), "the next run must stop")
	})

	t.Run("keeps the vehicle active through transient failures", func(t *testing.T) {
		for name, result := range map[string]struct {
			data json.RawMessage
			err  error
		}{
			"vehicle asleep":  {err: core.ErrVehicleUnavailable},
			"Tesla error":     {err: errors.New("tesla 503")},
			"DIS send failed": {data: json.RawMessage(`{"response":{}}`)},
		} {
			t.Run(name, func(t *testing.T) {
				repo := &fakeVehicleRepo{device: activeDevice(t, cip)}
				fleetAPI := new(test.MockTeslaFleetAPIService)
				fleetAPI.On("GetLegacyVehicleData", mock.Anything, "access-token", testVIN).Return(result.data, result.err)

				newTestWorker(nil, repo, fleetAPI).poll(ctx, &logger, repo.device)
				require.Empty(t, repo.savedStatus)
				require.True(t, shouldContinueLegacyPolling(repo.device))
			})
		}
	})
}
