package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/DIMO-Network/shared/db"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/IBM/sarama"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/boil"
)

const (
	teslaIntegrationID int64 = 2
	contractEventType        = "zone.dimo.contract.event"
)

type contractEventData struct {
	EventName      string          `json:"eventName"`
	EventSignature string          `json:"eventSignature"`
	Arguments      json.RawMessage `json:"arguments"`
}

type Processor struct {
	pdb                              db.Store
	topic                            string
	logger                           *zerolog.Logger
	syntheticDeviceNodeMintedEventID common.Hash
}

func New(
	pdb db.Store,
	topic string,
	logger *zerolog.Logger) *Processor {
	syntheticDeviceNodeMintedEventID := common.HexToHash("0x5a560c1adda92bd6cbf9c891dc38e9e2973b7963493f2364caa40a4218346280")

	return &Processor{
		pdb:                              pdb,
		logger:                           logger,
		topic:                            topic,
		syntheticDeviceNodeMintedEventID: syntheticDeviceNodeMintedEventID,
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

			var event cloudevent.CloudEvent[contractEventData]
			if err := json.Unmarshal(msg.Value, &event); err != nil {
				p.logger.Err(err).Msg("failed to parse contract event")
				session.MarkMessage(msg, "")
				continue
			}

			if event.Type != contractEventType {
				session.MarkMessage(msg, "")
				continue
			}

			switch event.Data.EventSignature {
			case p.syntheticDeviceNodeMintedEventID.Hex():
				if err := p.handleSyntheticDeviceNodeMinted(session.Context(), event.Data.Arguments); err != nil {
					p.logger.Err(err).Msg("failed to process tesla device mint")
					continue
				}
				session.MarkMessage(msg, "")
			default:
				session.MarkMessage(msg, "")

			}

		}
	}
}

func (p Processor) handleSyntheticDeviceNodeMinted(ctx context.Context, data json.RawMessage) error {
	var mint SyntheticDeviceNodeMinted
	if err := json.Unmarshal(data, &mint); err != nil {
		return fmt.Errorf("failed to parse tesla mint event: %w", err)
	}

	if mint.IntegrationNode.Int64() != teslaIntegrationID { // only tesla mints
		p.logger.Debug().Int64("integrationNode", mint.IntegrationNode.Int64()).Msg("only process tesla mints")
		return nil
	}

	synthDeviceAddr := mint.SyntheticDeviceAddress
	partSynthDev, err := models.SyntheticDevices(
		models.SyntheticDeviceWhere.Address.EQ(synthDeviceAddr.Bytes()),
		models.SyntheticDeviceWhere.VehicleTokenID.IsNull(),
	).One(ctx, p.pdb.DBS().Reader)
	if err != nil {
		return fmt.Errorf("failed to find partial device: %w", err)
	}

	partSynthDev.VehicleTokenID = null.IntFrom(int(mint.VehicleNode.Int64()))
	partSynthDev.TokenID = null.IntFrom(int(mint.SyntheticDeviceNode.Int64()))
	_, err = partSynthDev.Update(ctx, p.pdb.DBS().Writer, boil.Infer())
	if err != nil {
		return fmt.Errorf("failed to update table for sythetic device %s: %w", common.Bytes2Hex(partSynthDev.Address), err)
	}
	return nil
}

type SyntheticDeviceNodeMinted struct {
	IntegrationNode        *big.Int       `json:"integrationNode"`
	SyntheticDeviceNode    *big.Int       `json:"syntheticDeviceNode"`
	VehicleNode            *big.Int       `json:"vehicleNode"`
	SyntheticDeviceAddress common.Address `json:"syntheticDeviceAddress"`
	Owner                  common.Address `json:"owner"`
}
