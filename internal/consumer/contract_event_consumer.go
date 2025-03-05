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
	teslaIntegrationID               = 2
	contractEventType                = "zone.dimo.contract.event"
	syntheticDeviceNodeMinted        = "SyntheticDeviceNodeMinted"
	syntheticDeviceNodeMintedEventID = "0x5a560c1adda92bd6cbf9c891dc38e9e2973b7963493f2364caa40a4218346280"
	syntheticDeviceNodeBurnedEventID = "0xe4edc3c1f917608d486e02df63af34158f185b78cef44615aebee26c09064122"
)

type contractEventData struct {
	EventName      string          `json:"eventName"`
	EventSignature string          `json:"eventSignature"`
	Arguments      json.RawMessage `json:"arguments"`
}

type Processor struct {
	pdb                              db.Store
	logger                           *zerolog.Logger
	syntheticDeviceNodeMintedEventID string
	syntheticDeviceNodeBurnedEventID string
}

func New(
	pdb db.Store,
	logger *zerolog.Logger) *Processor {
	return &Processor{
		pdb:                              pdb,
		logger:                           logger,
		syntheticDeviceNodeMintedEventID: syntheticDeviceNodeMintedEventID,
		syntheticDeviceNodeBurnedEventID: syntheticDeviceNodeBurnedEventID,
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
			case p.syntheticDeviceNodeMintedEventID:
				if err := p.handleSyntheticDeviceNodeMinted(session.Context(), event.Data.Arguments); err != nil {
					p.logger.Err(err).Msg("failed to process tesla device mint")
					continue
				}
				session.MarkMessage(msg, "")
			case p.syntheticDeviceNodeBurnedEventID:
				if err := p.handleSyntheticDeviceNodeBurned(session.Context(), event.Data.Arguments); err != nil {
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

type SyntheticDeviceNodeMinted struct {
	IntegrationNode        *big.Int       `json:"integrationNode"`
	SyntheticDeviceNode    *big.Int       `json:"syntheticDeviceNode"`
	VehicleNode            *big.Int       `json:"vehicleNode"`
	SyntheticDeviceAddress common.Address `json:"syntheticDeviceAddress"`
	Owner                  common.Address `json:"owner"`
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
	return fmt.Errorf("failed to update table for sythetic device %s: %w", partSynthDev.Address, err)
}

type SyntheticDeviceNodeBurned struct {
	SyntheticDeviceNode *big.Int       `json:"syntheticDeviceNode"`
	VehicleNode         *big.Int       `json:"vehicleNode"`
	Owner               common.Address `json:"owner"`
}

func (p Processor) handleSyntheticDeviceNodeBurned(ctx context.Context, data json.RawMessage) error {
	var args SyntheticDeviceNodeBurned
	if err := json.Unmarshal(data, &args); err != nil {
		return fmt.Errorf("failed to parse device burn event: %w", err)
	}

	delCount, err := models.SyntheticDevices(
		models.SyntheticDeviceWhere.TokenID.EQ(
			null.IntFrom(int(args.SyntheticDeviceNode.Int64()))),
	).DeleteAll(ctx, p.pdb.DBS().Writer)
	if err != nil {
		return fmt.Errorf("failed to delete synthetic device node %d: %w", args.SyntheticDeviceNode.Int64(), err)
	}

	if delCount != 1 {
		return fmt.Errorf("synthetic device node %d burn even deleted unexpected number of devices: %d", args.SyntheticDeviceNode.Int64(), delCount)
	}

	return nil
}
