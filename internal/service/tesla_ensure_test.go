package service

import (
	"context"
	"testing"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/ethereum/go-ethereum/common"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockVehicleRepository struct {
	mock.Mock
}

func (m *mockVehicleRepository) GetSyntheticDeviceByVin(ctx context.Context, vin string) (*dbmodels.SyntheticDevice, error) {
	panic("not implemented")
}

func (m *mockVehicleRepository) GetSyntheticDevicesByVIN(ctx context.Context, vin string) (dbmodels.SyntheticDeviceSlice, error) {
	panic("not implemented")
}

func (m *mockVehicleRepository) GetSyntheticDevicesByVins(ctx context.Context, vins []string) (dbmodels.SyntheticDeviceSlice, error) {
	panic("not implemented")
}

func (m *mockVehicleRepository) GetSyntheticDevicesBySubscriptionStatus(ctx context.Context, status string) (dbmodels.SyntheticDeviceSlice, error) {
	panic("not implemented")
}

func (m *mockVehicleRepository) GetSyntheticDeviceByTokenID(ctx context.Context, tokenID int64) (*dbmodels.SyntheticDevice, error) {
	args := m.Called(ctx, tokenID)
	if args.Get(0) != nil {
		return args.Get(0).(*dbmodels.SyntheticDevice), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockVehicleRepository) GetSyntheticDeviceByAddress(ctx context.Context, address common.Address) (*dbmodels.SyntheticDevice, error) {
	panic("not implemented")
}

func (m *mockVehicleRepository) UpdateSyntheticDeviceSubscriptionStatus(ctx context.Context, device *dbmodels.SyntheticDevice, status string) error {
	args := m.Called(ctx, device, status)
	if args.Error(0) == nil {
		device.SubscriptionStatus = null.StringFrom(status)
	}
	return args.Error(0)
}

func (m *mockVehicleRepository) UpdateSyntheticDeviceCredentials(ctx context.Context, device *dbmodels.SyntheticDevice, creds *repository.Credential) error {
	args := m.Called(ctx, device, creds)
	return args.Error(0)
}

func (m *mockVehicleRepository) InsertSyntheticDevice(ctx context.Context, device *dbmodels.SyntheticDevice) error {
	panic("not implemented")
}

func (m *mockVehicleRepository) DeleteSyntheticDevice(ctx context.Context, address []byte) error {
	panic("not implemented")
}

type mockLegacyPollScheduler struct {
	mock.Mock
}

func (m *mockLegacyPollScheduler) ScheduleLegacyPoll(ctx context.Context, device *dbmodels.SyntheticDevice) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func TestEnsureVehicleDataFlow(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.New(nil)
	cip := new(cipher.ROT13Cipher)

	makeDevice := func(status string) *dbmodels.SyntheticDevice {
		access, _ := cip.Encrypt("mockAccessToken")
		refresh, _ := cip.Encrypt("mockRefreshToken")
		return &dbmodels.SyntheticDevice{
			Vin:             "1HGCM82633A123456",
			VehicleTokenID:  null.NewInt(789, true),
			TokenID:         null.NewInt(456, true),
			AccessToken:     null.StringFrom(access),
			RefreshToken:    null.StringFrom(refresh),
			AccessExpiresAt: null.TimeFrom(time.Now().Add(time.Hour)),
			RefreshExpiresAt: null.TimeFrom(time.Now().Add(time.Hour)),
			SubscriptionStatus: null.StringFrom(status),
		}
	}

	t.Run("streaming path marks active", func(t *testing.T) {
		vehicleRepo := new(mockVehicleRepository)
		fleetAPI := new(repository_test_MockTeslaFleetAPIServiceAdapter)
		pollScheduler := new(mockLegacyPollScheduler)
		sd := makeDevice("pending")

		vehicleRepo.On("GetSyntheticDeviceByTokenID", mock.Anything, int64(789)).Return(sd, nil)
		fleetAPI.On("VirtualKeyConnectionStatus", mock.Anything, "mockAccessToken", sd.Vin).Return(&core.VehicleFleetStatus{
			VehicleCommandProtocolRequired: true,
			KeyPaired:                      true,
		}, nil)
		fleetAPI.On("GetTelemetrySubscriptionStatus", mock.Anything, "mockAccessToken", sd.Vin).Return(&core.VehicleTelemetryStatus{}, nil)
		fleetAPI.On("SubscribeForTelemetryData", mock.Anything, "mockAccessToken", sd.Vin).Return(nil)
		vehicleRepo.On("UpdateSyntheticDeviceSubscriptionStatus", mock.Anything, sd, "active").Return(nil)

		tokenManager := core.NewTeslaTokenManager(cip, vehicleRepo, fleetAPI, &logger)
		svc := NewTeslaService(&config.Settings{}, &logger, &repository.Repositories{Vehicle: vehicleRepo}, fleetAPI, nil, nil, pollScheduler, *tokenManager)

		err := svc.EnsureVehicleDataFlow(ctx, 789)
		require.NoError(t, err)
		require.Equal(t, "active", sd.SubscriptionStatus.String)
	})

	t.Run("already configured streaming path skips subscribe", func(t *testing.T) {
		vehicleRepo := new(mockVehicleRepository)
		fleetAPI := new(repository_test_MockTeslaFleetAPIServiceAdapter)
		pollScheduler := new(mockLegacyPollScheduler)
		sd := makeDevice("pending")

		vehicleRepo.On("GetSyntheticDeviceByTokenID", mock.Anything, int64(789)).Return(sd, nil)
		fleetAPI.On("VirtualKeyConnectionStatus", mock.Anything, "mockAccessToken", sd.Vin).Return(&core.VehicleFleetStatus{
			VehicleCommandProtocolRequired: true,
			KeyPaired:                      true,
		}, nil)
		fleetAPI.On("GetTelemetrySubscriptionStatus", mock.Anything, "mockAccessToken", sd.Vin).Return(&core.VehicleTelemetryStatus{Configured: true}, nil)
		vehicleRepo.On("UpdateSyntheticDeviceSubscriptionStatus", mock.Anything, sd, "active").Return(nil)

		tokenManager := core.NewTeslaTokenManager(cip, vehicleRepo, fleetAPI, &logger)
		svc := NewTeslaService(&config.Settings{}, &logger, &repository.Repositories{Vehicle: vehicleRepo}, fleetAPI, nil, nil, pollScheduler, *tokenManager)

		err := svc.EnsureVehicleDataFlow(ctx, 789)
		require.NoError(t, err)
		require.Equal(t, "active", sd.SubscriptionStatus.String)
		fleetAPI.AssertNotCalled(t, "SubscribeForTelemetryData", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("polling path marks active", func(t *testing.T) {
		vehicleRepo := new(mockVehicleRepository)
		fleetAPI := new(repository_test_MockTeslaFleetAPIServiceAdapter)
		pollScheduler := new(mockLegacyPollScheduler)
		sd := makeDevice("pending")

		vehicleRepo.On("GetSyntheticDeviceByTokenID", mock.Anything, int64(789)).Return(sd, nil)
		fleetAPI.On("VirtualKeyConnectionStatus", mock.Anything, "mockAccessToken", sd.Vin).Return(&core.VehicleFleetStatus{
			VehicleCommandProtocolRequired: false,
			FirmwareVersion:                "2025.21.11",
			DiscountedDeviceData:           true,
		}, nil)
		pollScheduler.On("ScheduleLegacyPoll", mock.Anything, sd).Return(nil)
		vehicleRepo.On("UpdateSyntheticDeviceSubscriptionStatus", mock.Anything, sd, "active").Return(nil)

		tokenManager := core.NewTeslaTokenManager(cip, vehicleRepo, fleetAPI, &logger)
		svc := NewTeslaService(&config.Settings{}, &logger, &repository.Repositories{Vehicle: vehicleRepo}, fleetAPI, nil, nil, pollScheduler, *tokenManager)

		err := svc.EnsureVehicleDataFlow(ctx, 789)
		require.NoError(t, err)
		require.Equal(t, "active", sd.SubscriptionStatus.String)
	})

	t.Run("not ready leaves status alone", func(t *testing.T) {
		vehicleRepo := new(mockVehicleRepository)
		fleetAPI := new(repository_test_MockTeslaFleetAPIServiceAdapter)
		pollScheduler := new(mockLegacyPollScheduler)
		sd := makeDevice("pending")

		vehicleRepo.On("GetSyntheticDeviceByTokenID", mock.Anything, int64(789)).Return(sd, nil)
		fleetAPI.On("VirtualKeyConnectionStatus", mock.Anything, "mockAccessToken", sd.Vin).Return(&core.VehicleFleetStatus{
			VehicleCommandProtocolRequired: true,
			KeyPaired:                      false,
		}, nil)

		tokenManager := core.NewTeslaTokenManager(cip, vehicleRepo, fleetAPI, &logger)
		svc := NewTeslaService(&config.Settings{}, &logger, &repository.Repositories{Vehicle: vehicleRepo}, fleetAPI, nil, nil, pollScheduler, *tokenManager)

		err := svc.EnsureVehicleDataFlow(ctx, 789)
		require.ErrorIs(t, err, core.ErrTelemetryNotReady)
		require.Equal(t, "pending", sd.SubscriptionStatus.String)
		vehicleRepo.AssertNotCalled(t, "UpdateSyntheticDeviceSubscriptionStatus", mock.Anything, mock.Anything, "active")
	})
}

type repository_test_MockTeslaFleetAPIServiceAdapter struct {
	mock.Mock
}

func (m *repository_test_MockTeslaFleetAPIServiceAdapter) CompleteTeslaAuthCodeExchange(ctx context.Context, authCode, redirectURI string) (*core.TeslaAuthCodeResponse, error) {
	panic("not implemented")
}

func (m *repository_test_MockTeslaFleetAPIServiceAdapter) GetVehicles(ctx context.Context, token string) ([]core.TeslaVehicle, error) {
	panic("not implemented")
}

func (m *repository_test_MockTeslaFleetAPIServiceAdapter) GetVehicle(ctx context.Context, token string, vehicleID int) (*core.TeslaVehicle, error) {
	panic("not implemented")
}

func (m *repository_test_MockTeslaFleetAPIServiceAdapter) GetLegacyVehicleData(ctx context.Context, token, vin string) (json.RawMessage, error) {
	panic("not implemented")
}

func (m *repository_test_MockTeslaFleetAPIServiceAdapter) WakeUpVehicle(ctx context.Context, token string, vin string) (*core.TeslaVehicle, error) {
	panic("not implemented")
}

func (m *repository_test_MockTeslaFleetAPIServiceAdapter) VirtualKeyConnectionStatus(ctx context.Context, token, vin string) (*core.VehicleFleetStatus, error) {
	args := m.Called(ctx, token, vin)
	if args.Get(0) != nil {
		return args.Get(0).(*core.VehicleFleetStatus), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *repository_test_MockTeslaFleetAPIServiceAdapter) SubscribeForTelemetryData(ctx context.Context, token, vin string) error {
	args := m.Called(ctx, token, vin)
	return args.Error(0)
}

func (m *repository_test_MockTeslaFleetAPIServiceAdapter) UnSubscribeFromTelemetryData(ctx context.Context, token, vin string) error {
	panic("not implemented")
}

func (m *repository_test_MockTeslaFleetAPIServiceAdapter) GetTelemetrySubscriptionStatus(ctx context.Context, token, vin string) (*core.VehicleTelemetryStatus, error) {
	args := m.Called(ctx, token, vin)
	if args.Get(0) != nil {
		return args.Get(0).(*core.VehicleTelemetryStatus), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *repository_test_MockTeslaFleetAPIServiceAdapter) GetPartnersToken(ctx context.Context) (*core.PartnersAccessTokenResponse, error) {
	panic("not implemented")
}

func (m *repository_test_MockTeslaFleetAPIServiceAdapter) RefreshToken(ctx context.Context, refreshToken string) (*core.RefreshTokenResp, error) {
	panic("not implemented")
}

func (m *repository_test_MockTeslaFleetAPIServiceAdapter) ExecuteCommand(ctx context.Context, token, vin, command string) error {
	panic("not implemented")
}
