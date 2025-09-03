package credlistener

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/shared/pkg/sdtask"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/IBM/sarama"
	"github.com/aarondl/null/v8"
	"github.com/rs/zerolog"
)

type Consumer struct {
	dbs    db.Store
	logger *zerolog.Logger
}

func New(dbs db.Store, logger *zerolog.Logger) *Consumer {
	return &Consumer{dbs: dbs, logger: logger}
}

func (c *Consumer) Setup(_ sarama.ConsumerGroupSession) error   { return nil }
func (c *Consumer) Cleanup(_ sarama.ConsumerGroupSession) error { return nil }
func (c *Consumer) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for {
		select {
		case msg := <-claim.Messages():
			err := c.Handle(session.Context(), msg)
			if err != nil {
				c.logger.Err(err).Msg("Credential consumer error.")
				// We're just going to keep going for now. See you in 8 hours?
				// TODO(elffjs): Proper retry behavior. Never give up.
			}
			if session.Context().Err() != nil {
				return nil
			}
			session.MarkMessage(msg, "")
		case <-session.Context().Done():
			return nil
		}
	}
}

func (c *Consumer) Handle(ctx context.Context, msg *sarama.ConsumerMessage) error {
	var ce cloudevent.CloudEvent[sdtask.CredentialData]

	err := json.Unmarshal(msg.Value, &ce)
	if err != nil {
		c.logger.Warn().
			Err(err).
			RawJSON("message", msg.Value).
			Msgf("Couldn't parse credential message.")
		return nil
	}

	cd := ce.Data
	sd := cd.SyntheticDevice

	if sd == nil {
		c.logger.Warn().Msgf("Credential message has no synthetic device information.")
		return nil
	}

	if sd.IntegrationTokenID != 2 {
		// Don't expect this to be possible right now, but let's see.
		// This is an outdated identifier, obviously.
		return nil
	}

	cols := models.SyntheticDeviceColumns

	// Tokens are encrypted
	rowCount, err := models.SyntheticDevices(models.SyntheticDeviceWhere.TokenID.EQ(null.IntFrom(sd.TokenID))).UpdateAll(ctx, c.dbs.DBS().Writer, models.M{
		cols.AccessToken:      null.StringFrom(cd.AccessToken),
		cols.AccessExpiresAt:  null.TimeFrom(cd.Expiry),
		cols.RefreshToken:     null.StringFrom(cd.RefreshToken),
		cols.RefreshExpiresAt: null.TimeFrom(cd.Expiry.Add(-8*time.Hour + 3*30*24*time.Hour)),
	})
	if err != nil {
		return fmt.Errorf("failed to update credentials in database: %w", err)
	}

	if rowCount == 0 {
		c.logger.Warn().Int("sdId", sd.TokenID).Msgf("Could not find synthetic device to update.")
	}

	return nil
}
