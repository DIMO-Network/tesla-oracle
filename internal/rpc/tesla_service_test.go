package rpc

import (
	"context"
	"testing"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	grpcpb "github.com/DIMO-Network/tesla-oracle/pkg/grpc"
	"github.com/aarondl/null/v8"
	"github.com/ethereum/go-ethereum/common"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockRPCVehicleRepository struct {
	mock.Mock
}

func (m *mockRPCVehicleRepository) GetSyntheticDeviceByVin(ctx context.Context, vin string) (*dbmodels.SyntheticDevice, error) {
	panic("not implemented")
}

func (m *mockRPCVehicleRepository) GetSyntheticDevicesByVIN(ctx context.Context, vin string) (dbmodels.SyntheticDeviceSlice, error) {
	panic("not implemented")
}

func (m *mockRPCVehicleRepository) GetSyntheticDevicesByVins(ctx context.Context, vins []string) (dbmodels.SyntheticDeviceSlice, error) {
	panic("not implemented")
}

func (m *mockRPCVehicleRepository) GetSyntheticDevicesBySubscriptionStatus(ctx context.Context, status string) (dbmodels.SyntheticDeviceSlice, error) {
	panic("not implemented")
}

func (m *mockRPCVehicleRepository) GetSyntheticDeviceByTokenID(ctx context.Context, tokenID int64) (*dbmodels.SyntheticDevice, error) {
	args := m.Called(ctx, tokenID)
	if args.Get(0) != nil {
		return args.Get(0).(*dbmodels.SyntheticDevice), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockRPCVehicleRepository) GetSyntheticDeviceByAddress(ctx context.Context, address common.Address) (*dbmodels.SyntheticDevice, error) {
	panic("not implemented")
}

func (m *mockRPCVehicleRepository) UpdateSyntheticDeviceSubscriptionStatus(ctx context.Context, device *dbmodels.SyntheticDevice, status string) error {
	panic("not implemented")
}

func (m *mockRPCVehicleRepository) UpdateSyntheticDeviceCredentials(ctx context.Context, device *dbmodels.SyntheticDevice, creds *repository.Credential) error {
	args := m.Called(ctx, device, creds)
	return args.Error(0)
}

func (m *mockRPCVehicleRepository) InsertSyntheticDevice(ctx context.Context, device *dbmodels.SyntheticDevice) error {
	panic("not implemented")
}

func (m *mockRPCVehicleRepository) DeleteSyntheticDevice(ctx context.Context, address []byte) error {
	panic("not implemented")
}

type mockRPCTeslaFleetAPIService struct {
	mock.Mock
}

func (m *mockRPCTeslaFleetAPIService) CompleteTeslaAuthCodeExchange(ctx context.Context, authCode, redirectURI string) (*core.TeslaAuthCodeResponse, error) {
	panic("not implemented")
}

func (m *mockRPCTeslaFleetAPIService) GetVehicles(ctx context.Context, token string) ([]core.TeslaVehicle, error) {
	panic("not implemented")
}

func (m *mockRPCTeslaFleetAPIService) GetVehicle(ctx context.Context, token string, vehicleID int) (*core.TeslaVehicle, error) {
	panic("not implemented")
}

func (m *mockRPCTeslaFleetAPIService) GetLegacyVehicleData(ctx context.Context, token, vin string) (json.RawMessage, error) {
	panic("not implemented")
}

func (m *mockRPCTeslaFleetAPIService) WakeUpVehicle(ctx context.Context, token string, vin string) (*core.TeslaVehicle, error) {
	panic("not implemented")
}

func (m *mockRPCTeslaFleetAPIService) VirtualKeyConnectionStatus(ctx context.Context, token, vin string) (*core.VehicleFleetStatus, error) {
	args := m.Called(ctx, token, vin)
	if args.Get(0) != nil {
		return args.Get(0).(*core.VehicleFleetStatus), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockRPCTeslaFleetAPIService) SubscribeForTelemetryData(ctx context.Context, token, vin string) error {
	panic("not implemented")
}

func (m *mockRPCTeslaFleetAPIService) UnSubscribeFromTelemetryData(ctx context.Context, token, vin string) error {
	panic("not implemented")
}

func (m *mockRPCTeslaFleetAPIService) GetTelemetrySubscriptionStatus(ctx context.Context, token, vin string) (*core.VehicleTelemetryStatus, error) {
	panic("not implemented")
}

func (m *mockRPCTeslaFleetAPIService) GetPartnersToken(ctx context.Context) (*core.PartnersAccessTokenResponse, error) {
	panic("not implemented")
}

func (m *mockRPCTeslaFleetAPIService) RefreshToken(ctx context.Context, refreshToken string) (*core.RefreshTokenResp, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) != nil {
		return args.Get(0).(*core.RefreshTokenResp), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockRPCTeslaFleetAPIService) ExecuteCommand(ctx context.Context, token, vin, command string) error {
	panic("not implemented")
}

func TestGetFleetStatusByTokenId(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.New(nil)
	vehicleRepo := new(mockRPCVehicleRepository)
	fleetAPI := new(mockRPCTeslaFleetAPIService)
	cip := new(cipher.ROT13Cipher)
	tokenManager := core.NewTeslaTokenManager(cip, vehicleRepo, fleetAPI, &logger)

	svc := &TeslaRPCService{
		dbs:          func() *db.ReaderWriter { return nil },
		logger:       &logger,
		vehicles:     vehicleRepo,
		tokenManager: tokenManager,
		fleetAPI:     fleetAPI,
	}

	makeDevice := func() *dbmodels.SyntheticDevice {
		access, _ := cip.Encrypt("access-token")
		refresh, _ := cip.Encrypt("refresh-token")
		return &dbmodels.SyntheticDevice{
			Vin:              "5YJ3E1EA7KF317000",
			VehicleTokenID:   null.IntFrom(123),
			AccessToken:      null.StringFrom(access),
			RefreshToken:     null.StringFrom(refresh),
			AccessExpiresAt:  null.TimeFrom(time.Now().Add(time.Hour)),
			RefreshExpiresAt: null.TimeFrom(time.Now().Add(24 * time.Hour)),
		}
	}

	t.Run("returns parsed fleet status", func(t *testing.T) {
		sd := makeDevice()
		toggle := true
		vehicleRepo.On("GetSyntheticDeviceByTokenID", mock.Anything, int64(123)).Return(sd, nil).Once()
		fleetAPI.On("VirtualKeyConnectionStatus", mock.Anything, "access-token", sd.Vin).Return(&core.VehicleFleetStatus{
			KeyPaired:                          true,
			VehicleCommandProtocolRequired:     true,
			FirmwareVersion:                    "2025.20.1",
			DiscountedDeviceData:               true,
			FleetTelemetryVersion:              "V2",
			NumberOfKeys:                       3,
			SafetyScreenStreamingToggleEnabled: &toggle,
		}, nil).Once()

		resp, err := svc.GetFleetStatusByTokenId(ctx, &grpcpb.GetFleetStatusByTokenIdRequest{VehicleTokenId: 123})
		require.NoError(t, err)
		require.True(t, resp.KeyPaired)
		require.True(t, resp.VehicleCommandProtocolRequired)
		require.Equal(t, "2025.20.1", resp.FirmwareVersion)
		require.True(t, resp.DiscountedDeviceData)
		require.Equal(t, "V2", resp.FleetTelemetryVersion)
		require.Equal(t, uint32(3), resp.NumberOfKeys)
		require.NotNil(t, resp.SafetyScreenStreamingToggleEnabled)
		require.True(t, resp.SafetyScreenStreamingToggleEnabled.Value)
	})

	t.Run("missing toggle stays nil", func(t *testing.T) {
		sd := makeDevice()
		vehicleRepo.On("GetSyntheticDeviceByTokenID", mock.Anything, int64(123)).Return(sd, nil).Once()
		fleetAPI.On("VirtualKeyConnectionStatus", mock.Anything, "access-token", sd.Vin).Return(&core.VehicleFleetStatus{}, nil).Once()

		resp, err := svc.GetFleetStatusByTokenId(ctx, &grpcpb.GetFleetStatusByTokenIdRequest{VehicleTokenId: 123})
		require.NoError(t, err)
		require.Nil(t, resp.SafetyScreenStreamingToggleEnabled)
	})

	t.Run("unknown token id returns not found", func(t *testing.T) {
		vehicleRepo.On("GetSyntheticDeviceByTokenID", mock.Anything, int64(404)).Return(nil, repository.ErrVehicleNotFound).Once()

		_, err := svc.GetFleetStatusByTokenId(ctx, &grpcpb.GetFleetStatusByTokenIdRequest{VehicleTokenId: 404})
		require.Equal(t, codes.NotFound, status.Code(err))
	})

	t.Run("missing credentials returns failed precondition", func(t *testing.T) {
		vehicleRepo.On("GetSyntheticDeviceByTokenID", mock.Anything, int64(125)).Return(&dbmodels.SyntheticDevice{
			Vin:            "5YJ3E1EA7KF317001",
			VehicleTokenID: null.IntFrom(125),
		}, nil).Once()

		_, err := svc.GetFleetStatusByTokenId(ctx, &grpcpb.GetFleetStatusByTokenIdRequest{VehicleTokenId: 125})
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	})

	t.Run("token refresh failure returns unavailable", func(t *testing.T) {
		access, _ := cip.Encrypt("expired-access")
		refresh, _ := cip.Encrypt("refresh-token")
		sd := &dbmodels.SyntheticDevice{
			Vin:              "5YJ3E1EA7KF317002",
			VehicleTokenID:   null.IntFrom(126),
			AccessToken:      null.StringFrom(access),
			RefreshToken:     null.StringFrom(refresh),
			AccessExpiresAt:  null.TimeFrom(time.Now().Add(-time.Hour)),
			RefreshExpiresAt: null.TimeFrom(time.Now().Add(time.Hour)),
		}
		vehicleRepo.On("GetSyntheticDeviceByTokenID", mock.Anything, int64(126)).Return(sd, nil).Once()
		fleetAPI.On("RefreshToken", mock.Anything, "refresh-token").Return(nil, core.ErrTokenRefreshFailed).Once()

		_, err := svc.GetFleetStatusByTokenId(ctx, &grpcpb.GetFleetStatusByTokenIdRequest{VehicleTokenId: 126})
		require.Equal(t, codes.Unavailable, status.Code(err))
	})
}
