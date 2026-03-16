package workers

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/tesla-oracle/internal/telemetry"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/DIMO-Network/tesla-oracle/pkg/wallet"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

const LegacyFleetAPIDataVersion = "fleet_api/v1.0.0"

type LegacyPollSender struct {
	disClient           telemetry.Sender
	wallets             wallet.SDWalletsAPI
	vehicleContract     common.Address
	syntheticContract   common.Address
	teslaConnectionAddr string
	chainID             int
	logger              *zerolog.Logger
}

func NewLegacyPollSender(
	disClient telemetry.Sender,
	wallets wallet.SDWalletsAPI,
	vehicleContract common.Address,
	syntheticContract common.Address,
	teslaConnectionAddr string,
	chainID int,
	logger *zerolog.Logger,
) *LegacyPollSender {
	return &LegacyPollSender{
		disClient:           disClient,
		wallets:             wallets,
		vehicleContract:     vehicleContract,
		syntheticContract:   syntheticContract,
		teslaConnectionAddr: teslaConnectionAddr,
		chainID:             chainID,
		logger:              logger,
	}
}

func (s *LegacyPollSender) Send(ctx context.Context, device *dbmodels.SyntheticDevice, rawStatus json.RawMessage) error {
	if device == nil || !device.VehicleTokenID.Valid || !device.TokenID.Valid || !device.WalletChildNumber.Valid {
		return fmt.Errorf("synthetic device missing token metadata for DIS send")
	}

	keccak256Hash := crypto.Keccak256(rawStatus)
	signature, err := s.wallets.SignHash(ctx, keccak256Hash, uint32(device.WalletChildNumber.Int))
	if err != nil {
		return fmt.Errorf("sign legacy status payload: %w", err)
	}

	event := cloudevent.CloudEvent[json.RawMessage]{
		CloudEventHeader: cloudevent.CloudEventHeader{
			ID:          uuid.NewString(),
			Source:      s.teslaConnectionAddr,
			Producer:    s.syntheticDID(device.TokenID.Int).String(),
			Subject:     s.vehicleDID(device.VehicleTokenID.Int).String(),
			Time:        time.Now(),
			Type:        cloudevent.TypeStatus,
			DataVersion: LegacyFleetAPIDataVersion,
			Extras: map[string]any{
				"signature": hexutil.Encode(signature),
			},
		},
		Data: rawStatus,
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal legacy status event: %w", err)
	}

	if err := s.disClient.Send(ctx, body); err != nil {
		return fmt.Errorf("send legacy status event: %w", err)
	}

	s.logger.Debug().
		Int("vehicleTokenId", device.VehicleTokenID.Int).
		Int("syntheticTokenId", device.TokenID.Int).
		Str("vin", device.Vin).
		Msg("Sent legacy Tesla payload to DIS")

	return nil
}

func (s *LegacyPollSender) vehicleDID(vehicleTokenID int) cloudevent.ERC721DID {
	return cloudevent.ERC721DID{
		ChainID:         uint64(s.chainID),
		ContractAddress: s.vehicleContract,
		TokenID:         big.NewInt(int64(vehicleTokenID)),
	}
}

func (s *LegacyPollSender) syntheticDID(syntheticTokenID int) cloudevent.ERC721DID {
	return cloudevent.ERC721DID{
		ChainID:         uint64(s.chainID),
		ContractAddress: s.syntheticContract,
		TokenID:         big.NewInt(int64(syntheticTokenID)),
	}
}
