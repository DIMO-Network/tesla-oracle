package test

import (
	"context"

	"github.com/DIMO-Network/tesla-oracle/internal/core"
	mods "github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/mock"
)

// MockIdentityAPIService is a mock implementation of the IdentityAPIService interface.
type MockIdentityAPIService struct {
	mock.Mock
}

func (m *MockIdentityAPIService) GetCachedVehicleByTokenID(tokenID int64) (*mods.Vehicle, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockIdentityAPIService) FetchVehiclesByWalletAddress(address string) ([]mods.Vehicle, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockIdentityAPIService) GetDeviceDefinitionByID(id string) (*mods.DeviceDefinition, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockIdentityAPIService) GetCachedDeviceDefinitionByID(id string) (*mods.DeviceDefinition, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockIdentityAPIService) FetchVehicleByTokenID(tokenID int64) (*mods.Vehicle, error) {
	args := m.Called(tokenID)
	if args.Get(0) != nil {
		return args.Get(0).(*mods.Vehicle), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockIdentityAPIService) FetchDeviceDefinitionByID(deviceDefinitionID string) (*mods.DeviceDefinition, error) {
	args := m.Called(deviceDefinitionID)
	if args.Get(0) != nil {
		return args.Get(0).(*mods.DeviceDefinition), args.Error(1)
	}
	return nil, args.Error(1)
}

// MockCredStore is a mock implementation of the CredStore interface.
type MockCredStore struct {
	mock.Mock
}

func (m *MockCredStore) Retrieve(ctx context.Context, user common.Address) (*repository.Credential, error) {
	args := m.Called(ctx, user)
	return args.Get(0).(*repository.Credential), args.Error(1)
}

func (m *MockCredStore) RetrieveAndDelete(ctx context.Context, user common.Address) (*repository.Credential, error) {
	args := m.Called(ctx, user)
	return args.Get(0).(*repository.Credential), args.Error(1)
}

func (m *MockCredStore) EncryptTokens(credential *repository.Credential) (*repository.Credential, error) {
	args := m.Called(credential)
	return args.Get(0).(*repository.Credential), args.Error(1)
}

func (m *MockCredStore) RetrieveWithTokensEncrypted(ctx context.Context, user common.Address) (*repository.Credential, error) {
	args := m.Called(ctx, user)
	return args.Get(0).(*repository.Credential), args.Error(1)
}

func (m *MockCredStore) Store(ctx context.Context, user common.Address, cred *repository.Credential) error {
	args := m.Called(ctx, user, cred)
	return args.Error(0)
}

// MockTeslaFleetAPIService is a mock implementation of the TeslaFleetAPIService interface.
type MockTeslaFleetAPIService struct {
	mock.Mock
}

func (m *MockTeslaFleetAPIService) RefreshToken(ctx context.Context, refreshToken string) (*core.RefreshTokenResp, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockTeslaFleetAPIService) GetPartnersToken(ctx context.Context) (*core.PartnersAccessTokenResponse, error) {
	args := m.Called(ctx)
	if args.Get(0) != nil {
		return args.Get(0).(*core.PartnersAccessTokenResponse), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockTeslaFleetAPIService) CompleteTeslaAuthCodeExchange(ctx context.Context, authCode, redirectURI string) (*core.TeslaAuthCodeResponse, error) {
	args := m.Called(ctx, authCode, redirectURI)
	if args.Get(0) != nil {
		return args.Get(0).(*core.TeslaAuthCodeResponse), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockTeslaFleetAPIService) GetVehicles(ctx context.Context, token string) ([]core.TeslaVehicle, error) {
	args := m.Called(ctx, token)
	if args.Get(0) != nil {
		return args.Get(0).([]core.TeslaVehicle), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockTeslaFleetAPIService) GetVehicle(ctx context.Context, token string, vehicleID int) (*core.TeslaVehicle, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockTeslaFleetAPIService) WakeUpVehicle(ctx context.Context, token string, vin string) (*core.TeslaVehicle, error) {
	args := m.Called(ctx, token, vin)
	if args.Get(0) != nil {
		return args.Get(0).(*core.TeslaVehicle), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockTeslaFleetAPIService) VirtualKeyConnectionStatus(ctx context.Context, token, vin string) (*core.VehicleFleetStatus, error) {
	args := m.Called(ctx, token, vin)
	if args.Get(0) != nil {
		return args.Get(0).(*core.VehicleFleetStatus), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockTeslaFleetAPIService) UnSubscribeFromTelemetryData(ctx context.Context, token, vin string) error {
	args := m.Called(ctx, token, vin)
	return args.Error(0)
}

func (m *MockTeslaFleetAPIService) GetTelemetrySubscriptionStatus(ctx context.Context, token, vin string) (*core.VehicleTelemetryStatus, error) {
	args := m.Called(ctx, token, vin)
	if args.Get(0) != nil {
		return args.Get(0).(*core.VehicleTelemetryStatus), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockTeslaFleetAPIService) SubscribeForTelemetryData(ctx context.Context, accessToken, vin string) error {
	args := m.Called(ctx, accessToken, vin)
	return args.Error(0)
}

// MockDevicesGRPCService is a mock implementation of the DevicesGRPCService interface.
type MockDevicesGRPCService struct {
	mock.Mock
}

func (m *MockDevicesGRPCService) StartTeslaTask(ctx context.Context, tokenID int64) error {
	args := m.Called(ctx, tokenID)
	return args.Error(0)
}

func (m *MockDevicesGRPCService) StopTeslaTask(ctx context.Context, tokenID int64) error {
	args := m.Called(ctx, tokenID)
	return args.Error(0)
}

func (m *MockDevicesGRPCService) Close() error {
	args := m.Called()
	return args.Error(0)
}

type MockDeviceDefinitionsAPIService struct {
	mock.Mock
}

func (m *MockDeviceDefinitionsAPIService) DecodeVin(vin, countryCode string) (*service.DecodeVinResponse, error) {
	args := m.Called(vin, countryCode)
	if args.Get(0) != nil {
		return args.Get(0).(*service.DecodeVinResponse), args.Error(1)
	}
	return nil, args.Error(1)
}

// MockCipher is a mock implementation of a Cipher interface.
type MockCipher struct {
	mock.Mock
}

// Encrypt mocks the Encrypt method.
func (m *MockCipher) Encrypt(data string) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

// Decrypt mocks the Decrypt method.
func (m *MockCipher) Decrypt(data string) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

// MockCommandPublisher is a mock implementation of the CommandPublisher interface.
type MockCommandPublisher struct {
	mock.Mock
}

func (m *MockCommandPublisher) PublishCommand(ctx context.Context, sd *dbmodels.SyntheticDevice, command string) (string, error) {
	args := m.Called(ctx, sd, command)
	return args.String(0), args.Error(1)
}

// MockCommandRepository is a mock implementation of the CommandRepository interface.
type MockCommandRepository struct {
	mock.Mock
}

func (m *MockCommandRepository) SaveCommandRequest(ctx context.Context, request *dbmodels.DeviceCommandRequest) error {
	args := m.Called(ctx, request)
	return args.Error(0)
}

func (m *MockCommandRepository) UpdateCommandRequest(ctx context.Context, request *dbmodels.DeviceCommandRequest) error {
	args := m.Called(ctx, request)
	return args.Error(0)
}

func (m *MockCommandRepository) GetCommandRequest(ctx context.Context, taskID string) (*dbmodels.DeviceCommandRequest, error) {
	args := m.Called(ctx, taskID)
	if args.Get(0) != nil {
		return args.Get(0).(*dbmodels.DeviceCommandRequest), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockCommandRepository) GetCommandRequestsByVehicle(ctx context.Context, vehicleTokenID int, limit int) (dbmodels.DeviceCommandRequestSlice, error) {
	args := m.Called(ctx, vehicleTokenID, limit)
	if args.Get(0) != nil {
		return args.Get(0).(dbmodels.DeviceCommandRequestSlice), args.Error(1)
	}
	return nil, args.Error(1)
}

// MockRiverClient is a mock implementation of the River client
type MockRiverClient struct {
	mock.Mock
}

func (m *MockRiverClient) Insert(ctx context.Context, args interface{}, opts *river.InsertOpts) (*river.JobInsertResult, error) {
	mockArgs := m.Called(ctx, args, opts)
	if mockArgs.Get(0) != nil {
		// Create a real JobInsertResult with the mocked job ID
		jobID := mockArgs.Get(0).(int64)
		result := &river.JobInsertResult{
			Job: &river.Job[any]{
				ID: jobID,
			},
		}
		return result, mockArgs.Error(1)
	}
	return nil, mockArgs.Error(1)
}
