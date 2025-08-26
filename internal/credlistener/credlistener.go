package credlistener

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/shared/pkg/sdtask"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/rs/zerolog"
)

type Consumer struct {
	dbs    db.Store
	logger *zerolog.Logger
}

var credUpdateWhitelist = boil.Whitelist(
	models.SyntheticDeviceColumns.AccessToken,
	models.SyntheticDeviceColumns.AccessExpiresAt,
	models.SyntheticDeviceColumns.RefreshToken,
	models.SyntheticDeviceColumns.RefreshExpiresAt,
)

func (c *Consumer) Handle(ctx context.Context, msgValue []byte) error {
	var ce cloudevent.CloudEvent[sdtask.CredentialData]

	err := json.Unmarshal(msgValue, &ce)
	if err != nil {
		return fmt.Errorf("couldn't deserialize credentials")
	}

	cd := ce.Data
	sd := cd.SyntheticDevice

	if sd == nil {
		c.logger.Warn().Msgf("Credential message has no synthetic device information.")
		return nil
	}

	if sd.IntegrationTokenID != 2 {
		// Don't expect this to be possible right now, but let's see.
		return nil
	}

	sdm, err := models.SyntheticDevices(models.SyntheticDeviceWhere.TokenID.EQ(null.IntFrom(sd.TokenID))).One(ctx, c.dbs.DBS().Reader)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.logger.Warn().Int("sdId", sd.TokenID).Msg("Got a credential message for a synthetic device we don't know.")
			return nil
		}
		return err
	}

	sdm.AccessToken = null.StringFrom(cd.AccessToken)
	sdm.AccessExpiresAt = null.TimeFrom(cd.Expiry)
	sdm.RefreshToken = null.StringFrom(cd.RefreshToken)
	sdm.RefreshExpiresAt = null.TimeFrom(cd.Expiry.Add(-8*time.Hour + 3*30*24*time.Hour))

	// TODO(elffjs): Probably ought to check this row count.
	_, err = sdm.Update(ctx, c.dbs.DBS().Writer, credUpdateWhitelist)
	if err != nil {
		return err
	}

	return nil
}
