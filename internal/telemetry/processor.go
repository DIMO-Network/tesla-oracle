package telemetry

import (
	"time"

	"github.com/IBM/sarama"
	"github.com/rs/zerolog"
)

// Processor is a Sarama ConsumerGroupHandler that batches Tesla telemetry payloads and forwards them to DIS.
type Processor struct {
	batcher             *Batcher
	vinMap              *VinMap
	teslaTelemetryTopic string
	waitFor             time.Duration
	logger              *zerolog.Logger
}

func NewProcessor(
	batcher *Batcher,
	vinMap *VinMap,
	teslaTelemetryTopic string,
	batcherDurationSeconds int,
	logger *zerolog.Logger) *Processor {
	return &Processor{
		batcher:             batcher,
		vinMap:              vinMap,
		teslaTelemetryTopic: teslaTelemetryTopic,
		waitFor:             time.Duration(batcherDurationSeconds) * time.Second,
		logger:              logger,
	}
}

func (p Processor) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (p Processor) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }
func (p Processor) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	batcher := Batcher{
		batchByTokenID:      map[uint64]batch{},
		disClient:           p.batcher.disClient,
		swalletClient:       p.batcher.swalletClient,
		vehicleContract:     p.batcher.vehicleContract,
		synthDeviceContract: p.batcher.synthDeviceContract,
		teslaConnectionAddr: p.batcher.teslaConnectionAddr,
		chainID:             p.batcher.chainID,
		logger:              p.batcher.logger,
	}

	ticker := time.NewTicker(p.waitFor)
	var lastOff int64 = -1
	for {
		select {
		case <-session.Context().Done():
			return nil
		case msg, ok := <-claim.Messages():
			if !ok {
				p.logger.Info().Msg("message channel closed")
				return nil
			}

			vin := string(msg.Key)
			if len(vin) != 17 {
				p.logger.Warn().Str("vin", vin).Msg("invalid vin length. skipping.")
				continue
			}
			p.logger.Debug().Msgf("recieved data from vin: %s", vin)
			veh, err := p.vinMap.AddOrFetch(session.Context(), vin)
			if err != nil {
				p.logger.Err(err).Str("vin", vin).Msg("failed to fetch vehicle infos by vin")
				continue
			}

			select {
			case <-session.Context().Done():
				return nil
			default:
				batcher.Add(
					session.Context(),
					VehMetaData{
						synthDevices: veh.synthDevices,
						data:         msg.Value,
					})
			}
			lastOff = msg.Offset
		case <-ticker.C:
			start := time.Now()
			err := batcher.SendData(session.Context())
			if err != nil {
				p.logger.Err(err).Msg("failed to send messages to DIS")
				totalWindowProcessingDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
				continue
			}

			if lastOff != -1 {
				session.MarkOffset(claim.Topic(), claim.Partition(), lastOff+1, "")
			}
			totalWindowProcessingDuration.WithLabelValues("success").Observe(time.Since(start).Seconds())
		}
	}
}
