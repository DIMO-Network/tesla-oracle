package telemetry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/rs/zerolog"
)

type VINLookup interface {
	GetSyntheticDevicesByVIN(ctx context.Context, vin string) ([]service.SyntheticDeviceInfo, error)
}

type VINMap struct {
	data            map[string]*VehicleMetadata
	lookup          VINLookup
	logger          *zerolog.Logger
	mu              sync.RWMutex
	refreshInterval time.Duration
}

func NewVINMap(lookup VINLookup, mappingExpiration time.Duration, logger *zerolog.Logger) *VINMap {
	return &VINMap{
		lookup:          lookup,
		logger:          logger,
		refreshInterval: mappingExpiration,
		data:            map[string]*VehicleMetadata{},
	}
}

func (v *VINMap) AddOrFetch(ctx context.Context, vin string) (*VehicleMetadata, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	veh, ok := v.data[vin]
	if !ok || time.Since(veh.lastRefresh) >= v.refreshInterval {
		v.logger.Debug().Msgf("vin %s not in mapping, fetching from local lookup", vin)

		devices, err := v.lookup.GetSyntheticDevicesByVIN(ctx, vin)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch vin from local lookup: %w", err)
		}

		md := VehicleMetadata{
			lastRefresh: time.Now(),
		}
		for _, sd := range devices {
			md.synthDevices = append(md.synthDevices, syntheticDeviceMetadata{
				vehicleTokenID: sd.VehicleTokenID,
				walletChildNum: sd.WalletChildNum,
				tokenID:        sd.TokenID,
			})
		}

		v.data[vin] = &md
		return &md, nil
	}

	return veh, nil
}
