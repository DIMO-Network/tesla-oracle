package test

import (
	"context"

	mods "github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/ethereum/go-ethereum/common"
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

func (m *MockCredStore) Retrieve(ctx context.Context, user common.Address) (*service.Credential, error) {
	args := m.Called(ctx, user)
	return args.Get(0).(*service.Credential), args.Error(1)
}

func (m *MockCredStore) EncryptTokens(credential *service.Credential) (*service.Credential, error) {
	args := m.Called(credential)
	return args.Get(0).(*service.Credential), args.Error(1)
}

func (m *MockCredStore) RetrieveWithTokensEncrypted(ctx context.Context, user common.Address) (*service.Credential, error) {
	args := m.Called(ctx, user)
	return args.Get(0).(*service.Credential), args.Error(1)
}

func (m *MockCredStore) Store(ctx context.Context, user common.Address, cred *service.Credential) error {
	args := m.Called(ctx, user, cred)
	return args.Error(0)
}
