package service

import (
	"context"
	"errors"
	"testing"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockIdentityService struct {
	mock.Mock
}

func (m *mockIdentityService) GetCachedVehicleByTokenID(tokenID int64) (*models.Vehicle, error) {
	panic("not implemented")
}

func (m *mockIdentityService) FetchVehicleByTokenID(tokenID int64) (*models.Vehicle, error) {
	args := m.Called(tokenID)
	if args.Get(0) != nil {
		return args.Get(0).(*models.Vehicle), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockIdentityService) FetchVehiclesByWalletAddress(address string) ([]models.Vehicle, error) {
	panic("not implemented")
}

func (m *mockIdentityService) GetDeviceDefinitionByID(id string) (*models.DeviceDefinition, error) {
	panic("not implemented")
}

func (m *mockIdentityService) GetCachedDeviceDefinitionByID(id string) (*models.DeviceDefinition, error) {
	panic("not implemented")
}

func (m *mockIdentityService) FetchDeviceDefinitionByID(id string) (*models.DeviceDefinition, error) {
	panic("not implemented")
}

// Several vehicle NFTs, from different wallets, can each hold a connection to the
// same Tesla. Tesla keeps one fleet_telemetry_config per VIN for our app, so
// unsubscribing one connection must not delete it while another is still live.
func TestUnsubscribeFromTelemetrySharedVIN(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.New(nil)
	devLicense := common.HexToAddress("0x299671D2b32ED62Cc61ce65D8f2b9e4f78486B37")
	const vin = "7SAYGDEE1SA000013"
	const partnerToken = "partner-token"

	row := func(addr string, vehicleID, sdID int, status string) *dbmodels.SyntheticDevice {
		return &dbmodels.SyntheticDevice{
			Address:            common.HexToAddress(addr).Bytes(),
			Vin:                vin,
			VehicleTokenID:     null.IntFrom(vehicleID),
			TokenID:            null.IntFrom(sdID),
			SubscriptionStatus: null.StringFrom(status),
		}
	}
	const thisAddr = "0x0000000000000000000000000000000000001301"

	setup := func(t *testing.T, others dbmodels.SyntheticDeviceSlice, lookupErr error) (*TeslaService, *mockVehicleRepository, *repository_test_MockTeslaFleetAPIServiceAdapter, *dbmodels.SyntheticDevice) {
		vehicleRepo := new(mockVehicleRepository)
		fleetAPI := new(repository_test_MockTeslaFleetAPIServiceAdapter)
		identity := new(mockIdentityService)

		this := row(thisAddr, 501301, 601301, "active")
		identity.On("FetchVehicleByTokenID", int64(501301)).Return(&models.Vehicle{
			TokenID:         501301,
			Owner:           "0x1234567890AbcdEF1234567890aBcdef12345678",
			SyntheticDevice: models.SyntheticDevice{TokenID: 601301, Address: thisAddr},
		}, nil)
		fleetAPI.On("GetPartnersToken", mock.Anything).Return(&core.PartnersAccessTokenResponse{AccessToken: partnerToken}, nil)
		vehicleRepo.On("GetSyntheticDeviceByAddress", mock.Anything, common.HexToAddress(thisAddr)).Return(this, nil)
		if lookupErr != nil {
			vehicleRepo.On("GetSyntheticDevicesByVIN", mock.Anything, vin).Return(nil, lookupErr)
		} else {
			// The VIN's connected rows include this one.
			vehicleRepo.On("GetSyntheticDevicesByVIN", mock.Anything, vin).Return(append(dbmodels.SyntheticDeviceSlice{this}, others...), nil)
		}
		fleetAPI.On("UnSubscribeFromTelemetryData", mock.Anything, partnerToken, vin).Return(nil).Maybe()
		vehicleRepo.On("UpdateSyntheticDeviceSubscriptionStatus", mock.Anything, this, "inactive").Return(nil).Maybe()

		cip := new(cipher.ROT13Cipher)
		tokenManager := core.NewTeslaTokenManager(cip, vehicleRepo, fleetAPI, &logger)
		svc := NewTeslaService(&config.Settings{MobileAppDevLicense: devLicense}, &logger, &repository.Repositories{Vehicle: vehicleRepo}, fleetAPI, identity, nil, nil, *tokenManager)
		return svc, vehicleRepo, fleetAPI, this
	}

	t.Run("another active connection keeps Tesla's config", func(t *testing.T) {
		other := row("0x0000000000000000000000000000000000001302", 501302, 601302, "active")
		svc, vehicleRepo, fleetAPI, this := setup(t, dbmodels.SyntheticDeviceSlice{other}, nil)

		require.NoError(t, svc.UnsubscribeFromTelemetry(ctx, 501301, devLicense))

		fleetAPI.AssertNotCalled(t, "UnSubscribeFromTelemetryData", mock.Anything, mock.Anything, mock.Anything)
		vehicleRepo.AssertCalled(t, "UpdateSyntheticDeviceSubscriptionStatus", mock.Anything, this, "inactive")
		require.Equal(t, "inactive", this.SubscriptionStatus.String)
		require.Equal(t, "active", other.SubscriptionStatus.String)
	})

	// Onboarding leaves a connection "pending"; only the backend's subscribe call makes
	// it "active". A paying driver's connection is usually "pending", and it streams.
	t.Run("another pending connection keeps Tesla's config", func(t *testing.T) {
		other := row("0x0000000000000000000000000000000000001302", 501302, 601302, "pending")
		svc, vehicleRepo, fleetAPI, this := setup(t, dbmodels.SyntheticDeviceSlice{other}, nil)

		require.NoError(t, svc.UnsubscribeFromTelemetry(ctx, 501301, devLicense))

		fleetAPI.AssertNotCalled(t, "UnSubscribeFromTelemetryData", mock.Anything, mock.Anything, mock.Anything)
		vehicleRepo.AssertCalled(t, "UpdateSyntheticDeviceSubscriptionStatus", mock.Anything, this, "inactive")
		require.Equal(t, "pending", other.SubscriptionStatus.String)
	})

	t.Run("another connection with no status keeps Tesla's config", func(t *testing.T) {
		other := row("0x0000000000000000000000000000000000001302", 501302, 601302, "")
		other.SubscriptionStatus = null.String{}
		svc, _, fleetAPI, _ := setup(t, dbmodels.SyntheticDeviceSlice{other}, nil)

		require.NoError(t, svc.UnsubscribeFromTelemetry(ctx, 501301, devLicense))

		fleetAPI.AssertNotCalled(t, "UnSubscribeFromTelemetryData", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("unsubscribed connections don't keep it", func(t *testing.T) {
		others := dbmodels.SyntheticDeviceSlice{
			row("0x0000000000000000000000000000000000001302", 501302, 601302, "inactive"),
			row("0x0000000000000000000000000000000000001303", 501303, 601303, "inactive"),
		}
		svc, vehicleRepo, fleetAPI, this := setup(t, others, nil)

		require.NoError(t, svc.UnsubscribeFromTelemetry(ctx, 501301, devLicense))

		fleetAPI.AssertCalled(t, "UnSubscribeFromTelemetryData", mock.Anything, partnerToken, vin)
		vehicleRepo.AssertCalled(t, "UpdateSyntheticDeviceSubscriptionStatus", mock.Anything, this, "inactive")
	})

	t.Run("the only connection deletes Tesla's config", func(t *testing.T) {
		svc, vehicleRepo, fleetAPI, this := setup(t, nil, nil)

		require.NoError(t, svc.UnsubscribeFromTelemetry(ctx, 501301, devLicense))

		fleetAPI.AssertCalled(t, "UnSubscribeFromTelemetryData", mock.Anything, partnerToken, vin)
		vehicleRepo.AssertCalled(t, "UpdateSyntheticDeviceSubscriptionStatus", mock.Anything, this, "inactive")
	})

	t.Run("a failed lookup changes nothing, so the caller retries", func(t *testing.T) {
		svc, vehicleRepo, fleetAPI, this := setup(t, nil, errors.New("connection refused"))

		err := svc.UnsubscribeFromTelemetry(ctx, 501301, devLicense)
		require.Error(t, err)

		fleetAPI.AssertNotCalled(t, "UnSubscribeFromTelemetryData", mock.Anything, mock.Anything, mock.Anything)
		vehicleRepo.AssertNotCalled(t, "UpdateSyntheticDeviceSubscriptionStatus", mock.Anything, mock.Anything, mock.Anything)
		require.Equal(t, "active", this.SubscriptionStatus.String)
	})
}
