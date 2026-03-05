package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/tesla-oracle/pkg/wallet"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog"
	"github.com/segmentio/ksuid"
)

const (
	FleetTelemetryDataVersion = "fleet_telemetry/v1.0.0"
)

type VehMetaData struct {
	synthDevices []sdInfos
	lastRefresh  time.Time
	data         []byte
}

type sdInfos struct {
	tokenID        uint64
	walletChildNum uint64
	vehicleTokenID uint64
}

type Batcher struct {
	batchByTokenID      map[uint64]batch
	disClient           *DISClient
	swalletClient       wallet.SDWalletsAPI
	vehicleContract     common.Address
	synthDeviceContract common.Address
	teslaConnectionAddr string
	chainID             int
	logger              *zerolog.Logger
}

type batch struct {
	cloudEvent     cloudevent.CloudEvent[ceData]
	walletChildNum uint64
}

type ceData struct {
	Payloads [][]byte `json:"payloads"`
}

func NewBatcher(
	disClient *DISClient,
	swalletClient wallet.SDWalletsAPI,
	vehicleContract common.Address,
	synthDeviceContract common.Address,
	teslaConnectionAddr string,
	chainID int,
	logger *zerolog.Logger,
) *Batcher {
	return &Batcher{
		batchByTokenID:      map[uint64]batch{},
		disClient:           disClient,
		swalletClient:       swalletClient,
		vehicleContract:     vehicleContract,
		synthDeviceContract: synthDeviceContract,
		teslaConnectionAddr: teslaConnectionAddr,
		chainID:             chainID,
		logger:              logger,
	}
}

func (b *Batcher) Add(ctx context.Context, payload VehMetaData) {
	for _, sd := range payload.synthDevices {
		event, ok := b.batchByTokenID[sd.vehicleTokenID]
		if !ok {
			event = b.generateCloudEvent(sd.vehicleTokenID, sd.tokenID)
			event.walletChildNum = sd.walletChildNum
		}

		event.cloudEvent.Data.Payloads = append(event.cloudEvent.Data.Payloads, payload.data)
		b.batchByTokenID[sd.vehicleTokenID] = event
	}
}

// SendData transmits batched data to DIS.
func (b *Batcher) SendData(ctx context.Context) error {
	if len(b.batchByTokenID) == 0 {
		return nil
	}

	var errs error
	for vehTknID, batchedCloudEvent := range b.batchByTokenID {
		vehiclesTransmittingData.Inc()
		err := b.signAndSendStatus(ctx, batchedCloudEvent)
		if err != nil {
			b.logger.Err(err).Msgf("failed signing and sending status: %s", batchedCloudEvent.cloudEvent.Subject)
			errs = errors.Join(errs, fmt.Errorf("failed signing and sending status for %s: %w", batchedCloudEvent.cloudEvent.Subject, err))
			continue
		}

		delete(b.batchByTokenID, vehTknID)
	}

	return errs
}

func (b *Batcher) signAndSendStatus(ctx context.Context, batch batch) error {
	b.logger.Debug().Msg("sending status to dis")

	bts, err := b.signPayload(ctx, batch)
	if err != nil {
		return err
	}

	return b.disClient.Send(ctx, bts)
}

func (b *Batcher) signPayload(ctx context.Context, batch batch) ([]byte, error) {
	batchSize.Add(float64(len(batch.cloudEvent.Data.Payloads)))
	dataBytes, err := json.Marshal(batch.cloudEvent.Data)
	if err != nil {
		return nil, err
	}

	keccak256Hash := crypto.Keccak256(dataBytes)
	sig, err := b.swalletClient.SignHash(ctx, keccak256Hash, uint32(batch.walletChildNum))
	if err != nil {
		return nil, fmt.Errorf("failed to sign the batched status update for syntheticDevice: %d: %w", batch.walletChildNum, err)
	}

	header := batch.cloudEvent.CloudEventHeader
	header.Extras = map[string]any{
		"signature": hexutil.Encode(sig),
	}

	event := cloudevent.CloudEvent[json.RawMessage]{
		CloudEventHeader: header,
		Data:             dataBytes,
	}

	return json.Marshal(event)
}

func (b *Batcher) generateCloudEvent(vehicleTokenID, synthDeviceTokenID uint64) batch {
	vDID := cloudevent.ERC721DID{
		ChainID:         uint64(b.chainID),
		ContractAddress: b.vehicleContract,
		TokenID:         new(big.Int).SetUint64(vehicleTokenID),
	}

	sdDID := cloudevent.ERC721DID{
		ChainID:         uint64(b.chainID),
		ContractAddress: b.synthDeviceContract,
		TokenID:         new(big.Int).SetUint64(synthDeviceTokenID),
	}

	return batch{
		cloudEvent: cloudevent.CloudEvent[ceData]{
			CloudEventHeader: cloudevent.CloudEventHeader{
				ID:          ksuid.New().String(),
				Source:      b.teslaConnectionAddr,
				Producer:    sdDID.String(),
				Subject:     vDID.String(),
				Time:        time.Now(),
				Type:        cloudevent.TypeStatus,
				DataVersion: FleetTelemetryDataVersion,
			},
		},
	}
}
