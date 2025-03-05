package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/DIMO-Network/shared"
	"github.com/DIMO-Network/shared/db"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/IBM/sarama"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/boil"
)

const (
	TeslaIntegrationID        = 2
	ContractEventType         = "zone.dimo.contract.event"
	SyntheticDeviceNodeMinted = "SyntheticDeviceNodeMinted"
	SyntheticDeviceNodeBurned = "SyntheticDeviceNodeBurned"
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
			case SyntheticDeviceNodeBurned:
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
	partial, err := models.SyntheticDevices(
		models.SyntheticDeviceWhere.Address.EQ(walletAddr.Bytes()),
		models.SyntheticDeviceWhere.TokenID.IsNull(),
	).One(ctx, p.pdb.DBS().Reader)
	if err != nil {
		p.logger.Err(err).Msg("failed to find partial device")
		return err
	}

	full := models.SyntheticDevice{
		Vin:               partial.Vin,
		Address:           partial.Address,
		WalletChildNumber: partial.WalletChildNumber,
		VehicleTokenID:    null.IntFrom(mint.VehicleNode),
		TokenID:           null.IntFrom(mint.SyntheticDeviceNode),
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

	if _, err := models.SyntheticDevices(models.SyntheticDeviceWhere.TokenID.EQ(null.IntFrom(burn.VehicleNode))).DeleteAll(ctx, p.pdb.DBS().Writer); err != nil {
		if errors.Is(sql.ErrNoRows, err) {
			p.logger.Info().Msg("no vehicle record to delete")
			return nil
		}
		return err
	}

	return nil
}

type vehicleNodeBurnedArgs struct {
	SyntheticDeviceNode int `json:"syntheticDeviceNode"`
	VehicleNode         int `json:"vehicleNode"`
}

type syntheticDeviceNodeMinted struct {
	IntegrationNode        int            `json:"integrationNode"`
	SyntheticDeviceNode    int            `json:"syntheticDeviceNode"`
	VehicleNode            int            `json:"vehicleNode"`
	SyntheticDeviceAddress common.Address `json:"syntheticDeviceAddress"`
}
