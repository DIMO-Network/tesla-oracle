package services

import (
	"context"
	"encoding/json"

	"github.com/DIMO-Network/shared"
	"github.com/DIMO-Network/shared/db"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/IBM/sarama"
	"github.com/ericlagergren/decimal"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/types"
)

const (
	TeslaIntegrationID        = 2
	ContractEventType         = "zone.dimo.contract.event"
	SyntheticDeviceNodeMinted = "SyntheticDeviceNodeMinted"
	VehicleNodeBurned         = "VehicleNodeBurned"
)

type Processor struct {
	pdb    db.Store
	logger *zerolog.Logger
}

func NewProcessor(
	pdb db.Store,
	logger *zerolog.Logger) *Processor {
	return &Processor{
		pdb:    pdb,
		logger: logger,
	}
}

func (p Processor) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (p Processor) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }
func (p Processor) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for {
		select {
		case <-session.Context().Done():
			return nil
		case msg, ok := <-claim.Messages():
			if !ok {
				p.logger.Info().Msg("message channel closed")
				return nil
			}

			var event shared.CloudEvent[struct {
				EventName string
				Arguments json.RawMessage
			}]
			if err := json.Unmarshal(msg.Value, &event); err != nil {
				p.logger.Err(err).Msg("failed to parse contract event")
				session.MarkMessage(msg, "")
				continue
			}

			if event.Type != ContractEventType {
				session.MarkMessage(msg, "")
				continue
			}

			switch event.Data.EventName {
			case SyntheticDeviceNodeMinted:
				if err := p.handleSyntheticMintEvent(session.Context(), event.Data.Arguments); err != nil {
					p.logger.Err(err).Msg("failed to process tesla device mint")
					continue
				}
				session.MarkMessage(msg, "")
			case VehicleNodeBurned:
				if err := p.handleBurnEvent(session.Context(), event.Data.Arguments); err != nil {
					p.logger.Err(err).Msg("failed to process tesla device burn")
					continue
				}
				session.MarkMessage(msg, "")
			default:
				p.logger.Info().Msg("event type not recognized. continuing")
				session.MarkMessage(msg, "")
			}

		}
	}
}

func (p Processor) handleSyntheticMintEvent(ctx context.Context, data json.RawMessage) error {
	var mint syntheticDeviceNodeMinted
	if err := json.Unmarshal(data, &mint); err != nil {
		p.logger.Err(err).Msg("failed to marse tesla device mint event")
		return err
	}

	if mint.IntegrationNode != TeslaIntegrationID { // only tesla mints
		p.logger.Info().Msg("only process tesla mints")
		return nil
	}

	walletAddr := mint.SyntheticDeviceAddress
	partial, err := models.Devices(
		models.DeviceWhere.SyntheticDeviceAddress.EQ(walletAddr.Bytes()),
		models.DeviceWhere.TokenID.IsNull(),
	).One(ctx, p.pdb.DBS().Reader)
	if err != nil {
		p.logger.Err(err).Msg("failed to find partial device")
		return err
	}

	full := models.Device{
		Vin:                    partial.Vin,
		SyntheticDeviceAddress: partial.SyntheticDeviceAddress,
		WalletChildNum:         partial.WalletChildNum,
		TokenID:                types.NewNullDecimal(decimal.New(int64(mint.VehicleNode), 0)),
		SyntheticTokenID:       types.NewNullDecimal(decimal.New(int64(mint.SyntheticDeviceNode), 0)),
	}

	_, err = full.Update(ctx, p.pdb.DBS().Writer, boil.Infer())
	return err
}

func (p Processor) handleBurnEvent(ctx context.Context, data json.RawMessage) error {
	var burn vehicleNodeBurnedArgs
	if err := json.Unmarshal(data, &burn); err != nil {
		p.logger.Err(err).Msg("failed to marse device burn event")
		return err
	}

	if _, err := models.Devices(models.DeviceWhere.TokenID.EQ(types.NewNullDecimal(decimal.New(int64(burn.VehicleNode), 0)))).DeleteAll(ctx, p.pdb.DBS().Writer); err != nil {
		return err
	}

	return nil
}

type vehicleNodeBurnedArgs struct {
	VehicleNode int `json:"vehicleNode"`
}

type syntheticDeviceNodeMinted struct {
	IntegrationNode        int            `json:"integrationNode"`
	SyntheticDeviceNode    int            `json:"syntheticDeviceNode"`
	VehicleNode            int            `json:"vehicleNode"`
	SyntheticDeviceAddress common.Address `json:"syntheticDeviceAddress"`
}
