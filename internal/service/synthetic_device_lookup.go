package service

import (
	"context"

	"github.com/DIMO-Network/tesla-oracle/internal/repository"
)

type SyntheticDeviceInfo struct {
	VIN                string
	Address            []byte
	WalletChildNum     uint64
	VehicleTokenID     uint64
	TokenID            uint64
	SubscriptionStatus string
}

type SyntheticDeviceLookupService interface {
	GetSyntheticDevicesByVIN(ctx context.Context, vin string) ([]SyntheticDeviceInfo, error)
}

type syntheticDeviceLookupService struct {
	vehicles repository.VehicleRepository
}

func NewSyntheticDeviceLookupService(vehicles repository.VehicleRepository) SyntheticDeviceLookupService {
	return &syntheticDeviceLookupService{vehicles: vehicles}
}

func (s *syntheticDeviceLookupService) GetSyntheticDevicesByVIN(ctx context.Context, vin string) ([]SyntheticDeviceInfo, error) {
	devices, err := s.vehicles.GetSyntheticDevicesByVIN(ctx, vin)
	if err != nil {
		return nil, err
	}

	out := make([]SyntheticDeviceInfo, 0, len(devices))
	for _, dev := range devices {
		out = append(out, SyntheticDeviceInfo{
			VIN:                dev.Vin,
			Address:            dev.Address,
			WalletChildNum:     uint64(dev.WalletChildNumber.Int),
			VehicleTokenID:     uint64(dev.VehicleTokenID.Int),
			TokenID:            uint64(dev.TokenID.Int),
			SubscriptionStatus: dev.SubscriptionStatus.String,
		})
	}

	return out, nil
}
