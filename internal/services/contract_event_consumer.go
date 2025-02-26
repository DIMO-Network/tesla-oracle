package services

import (
	"context"
	"encoding/json"

	"github.com/DIMO-Network/shared"
	"github.com/DIMO-Network/shared/db"
	"github.com/DIMO-Network/shared/event/sdmint"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/IBM/sarama"
	"github.com/ericlagergren/decimal"
	"github.com/rs/zerolog"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/types"
)

const (
	TeslaIntegrationID = "2"
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

			var event shared.CloudEvent[json.RawMessage]
			if err := json.Unmarshal(msg.Value, &event); err != nil {
				p.logger.Err(err).Msg("failed to parse contract event")
				session.MarkMessage(msg, "")
				continue
			}

			switch event.Type {
			case sdmint.Type:
				if err := p.handleMintEvent(session.Context(), event.Data); err != nil {
					p.logger.Err(err).Msg("failed to process tesla device mint")
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

func (p Processor) handleMintEvent(ctx context.Context, data json.RawMessage) error {
	var sdmint sdmint.Data
	if err := json.Unmarshal(data, &sdmint); err != nil {
		p.logger.Err(err).Msg("failed to marse tesla device mint event")
		return err
	}

	if sdmint.Integration.IntegrationID != TeslaIntegrationID { // only tesla mints
		p.logger.Info().Msg("only process tesla mints")
		return nil
	}

	walletChildNum := types.NewDecimal(decimal.New(int64(sdmint.Device.WalletChildNumber), 0))
	partial, err := models.PartialDevices(models.PartialDeviceWhere.WalletChildNum.EQ(walletChildNum)).One(ctx, p.pdb.DBS().Reader)
	if err != nil {
		p.logger.Err(err).Msg("failed to find partial device")
		return err
	}

	full := models.Device{
		Vin:                    partial.Vin,
		SyntheticDeviceAddress: partial.SyntheticDeviceAddress,
		WalletChildNum:         partial.WalletChildNum,
		TokenID:                types.NewDecimal(decimal.New(int64(sdmint.Vehicle.TokenID), 0)),
		SyntheticTokenID:       types.NewDecimal(decimal.New(int64(sdmint.Device.TokenID), 0)),
	}

	return full.Insert(ctx, p.pdb.DBS().Writer, boil.Infer())
}
