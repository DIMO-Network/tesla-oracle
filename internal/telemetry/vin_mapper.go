package telemetry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/rs/zerolog"
)

// VinMap caches synthetic device lookups by VIN, refreshing periodically.
type VinMap struct {
	data            map[string]*VehMetaData
	dbs             func() *db.ReaderWriter
	logger          *zerolog.Logger
	mu              sync.RWMutex
	refreshInterval time.Duration
}

func NewVinMap(dbs func() *db.ReaderWriter, mappingExpiration time.Duration, logger *zerolog.Logger) *VinMap {
	return &VinMap{
		dbs:             dbs,
		logger:          logger,
		refreshInterval: mappingExpiration,
		data:            map[string]*VehMetaData{},
	}
}

func (v *VinMap) AddOrFetch(ctx context.Context, vin string) (*VehMetaData, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	veh, ok := v.data[vin]
	if !ok || time.Since(veh.lastRefresh) >= v.refreshInterval {
		v.logger.Debug().Msgf("vin %s not in mapping, fetching from db", vin)

		devices, err := models.SyntheticDevices(
			models.SyntheticDeviceWhere.Vin.EQ(vin),
			models.SyntheticDeviceWhere.VehicleTokenID.IsNotNull(),
			models.SyntheticDeviceWhere.TokenID.IsNotNull(),
		).All(ctx, v.dbs().Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch synthetic devices for vin %s: %w", vin, err)
		}

		md := VehMetaData{
			lastRefresh: time.Now(),
		}
		for _, dev := range devices {
			md.synthDevices = append(md.synthDevices, sdInfos{
				vehicleTokenID: uint64(dev.VehicleTokenID.Int),
				walletChildNum: uint64(dev.WalletChildNumber.Int),
				tokenID:        uint64(dev.TokenID.Int),
			})
		}

		v.data[vin] = &md
		return &md, nil
	}

	return veh, nil
}
