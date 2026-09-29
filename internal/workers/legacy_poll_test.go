package workers

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/test"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testVehicleTokenID = 170722
	testVIN            = "5YJSA1E26HF000001"
	testPollInterval   = 5 * time.Minute
)

// TestScheduleLegacyPoll inserts through a real River client, so River's own
// validation of LegacyTeslaPollArgs.InsertOpts runs exactly as it does in prod.
func TestScheduleLegacyPoll(t *testing.T) {
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

	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	require.NoError(t, err)

	logger := zerolog.Nop()
	scheduler := NewLegacyTeslaPollScheduler(client, &logger)
	device := &dbmodels.SyntheticDevice{VehicleTokenID: null.IntFrom(testVehicleTokenID), Vin: testVIN}

	require.NoError(t, scheduler.ScheduleLegacyPoll(ctx, device))
	// Starting data flow again (a reconnect) must not add a second poll loop.
	require.NoError(t, scheduler.ScheduleLegacyPoll(ctx, device))

	var jobs int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE kind = $1", LegacyTeslaPollArgs{}.Kind()).Scan(&jobs))
	require.Equal(t, 1, jobs)
}

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

func TestLegacyTeslaPollWorker(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.Nop()
	cip := new(cipher.ROT13Cipher)
	job := &river.Job[LegacyTeslaPollArgs]{
		JobRow: &rivertype.JobRow{ID: 1},
		Args:   LegacyTeslaPollArgs{VehicleTokenID: testVehicleTokenID, VIN: testVIN},
	}

	newWorker := func(repo *fakeVehicleRepo, fleetAPI *test.MockTeslaFleetAPIService) *LegacyTeslaPollWorker {
		tokenManager := core.NewTeslaTokenManager(cip, repo, fleetAPI, &logger)
		// A sender with no DIS client fails on devices without token metadata,
		// which is what the send-failure case relies on.
		sender := NewLegacyPollSender(nil, nil, common.Address{}, common.Address{}, "", 0, &logger)
		return NewLegacyTeslaPollWorker(fleetAPI, tokenManager, repo, sender, &logger, testPollInterval)
	}

	requireKeepsPolling := func(t *testing.T, err error) {
		t.Helper()
		var snooze *rivertype.JobSnoozeError
		require.ErrorAs(t, err, &snooze, "the job must snooze so the same job polls again")
		require.Equal(t, testPollInterval, snooze.Duration)
	}

	t.Run("keeps polling while the vehicle is asleep", func(t *testing.T) {
		repo := &fakeVehicleRepo{device: activeDevice(t, cip)}
		fleetAPI := new(test.MockTeslaFleetAPIService)
		fleetAPI.On("GetLegacyVehicleData", mock.Anything, "access-token", testVIN).Return(nil, core.ErrVehicleUnavailable)

		requireKeepsPolling(t, newWorker(repo, fleetAPI).Work(ctx, job))
	})

	t.Run("keeps polling after a transient Tesla error", func(t *testing.T) {
		repo := &fakeVehicleRepo{device: activeDevice(t, cip)}
		fleetAPI := new(test.MockTeslaFleetAPIService)
		fleetAPI.On("GetLegacyVehicleData", mock.Anything, "access-token", testVIN).Return(nil, errors.New("tesla 503"))

		requireKeepsPolling(t, newWorker(repo, fleetAPI).Work(ctx, job))
	})

	t.Run("keeps polling when sending the sample fails", func(t *testing.T) {
		repo := &fakeVehicleRepo{device: activeDevice(t, cip)}
		fleetAPI := new(test.MockTeslaFleetAPIService)
		fleetAPI.On("GetLegacyVehicleData", mock.Anything, "access-token", testVIN).Return(json.RawMessage(`{"response":{}}`), nil)

		requireKeepsPolling(t, newWorker(repo, fleetAPI).Work(ctx, job))
	})

	t.Run("keeps polling when the device lookup fails transiently", func(t *testing.T) {
		repo := &fakeVehicleRepo{getErr: errors.New("connection reset")}

		requireKeepsPolling(t, newWorker(repo, new(test.MockTeslaFleetAPIService)).Work(ctx, job))
	})

	t.Run("stops when the device is gone", func(t *testing.T) {
		repo := &fakeVehicleRepo{getErr: repository.ErrVehicleNotFound}

		require.NoError(t, newWorker(repo, new(test.MockTeslaFleetAPIService)).Work(ctx, job))
	})

	t.Run("stops when the device is no longer active", func(t *testing.T) {
		device := activeDevice(t, cip)
		device.SubscriptionStatus = null.StringFrom("inactive")
		fleetAPI := new(test.MockTeslaFleetAPIService)

		require.NoError(t, newWorker(&fakeVehicleRepo{device: device}, fleetAPI).Work(ctx, job))
		fleetAPI.AssertNotCalled(t, "GetLegacyVehicleData", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("stops and waits for reauth when Tesla rejects the token", func(t *testing.T) {
		repo := &fakeVehicleRepo{device: activeDevice(t, cip)}
		fleetAPI := new(test.MockTeslaFleetAPIService)
		fleetAPI.On("GetLegacyVehicleData", mock.Anything, "access-token", testVIN).Return(nil, core.ErrFleetAPIUnauthorized)

		require.NoError(t, newWorker(repo, fleetAPI).Work(ctx, job))
		require.Equal(t, "pending", repo.savedStatus)
	})

	t.Run("retries later when it cannot record that reauth is needed", func(t *testing.T) {
		repo := &fakeVehicleRepo{device: activeDevice(t, cip), updateErr: errors.New("connection reset")}
		fleetAPI := new(test.MockTeslaFleetAPIService)
		fleetAPI.On("GetLegacyVehicleData", mock.Anything, "access-token", testVIN).Return(nil, core.ErrFleetAPIUnauthorized)

		requireKeepsPolling(t, newWorker(repo, fleetAPI).Work(ctx, job))
	})
}
