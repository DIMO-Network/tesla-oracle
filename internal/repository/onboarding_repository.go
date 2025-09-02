package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/DIMO-Network/shared/pkg/db"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/rs/zerolog"
)

var (
	ErrOnboardingVehicleNotFound = errors.New("vehicle not found")
)

type onboardingRepository struct {
	db     *db.Store
	logger *zerolog.Logger
}

func NewOnboardingRepository(db *db.Store, logger *zerolog.Logger) OnboardingRepository {
	return &onboardingRepository{
		db:     db,
		logger: logger,
	}
}

// GetOnboardingByVin retrieves a vehicle by its VIN.
func (r *onboardingRepository) GetOnboardingByVin(ctx context.Context, vehicleID string) (*dbmodels.Onboarding, error) {
	tx, err := r.db.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		r.logger.Error().Err(err).Msgf("Failed to begin transaction for vehicle %s", vehicleID)
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.logger.Error().Err(rbErr).Msgf("GetOnboardingByVin: Failed to rollback transaction for vehicle %s", vehicleID)
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				r.logger.Error().Err(cmErr).Msgf("GetOnboardingByVin: Failed to commit transaction for vehicle %s", vehicleID)
			}
		}
	}()

	vin, err := dbmodels.Onboardings(dbmodels.OnboardingWhere.Vin.EQ(vehicleID)).One(ctx, tx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrOnboardingVehicleNotFound
		}
		r.logger.Error().Err(err).Msgf("Failed to check if vehicle %s has been processed", vehicleID)
		return nil, err
	}

	return vin, nil
}

// GetOnboardingsByVins retrieves vehicles by their VINs.
func (r *onboardingRepository) GetOnboardingsByVins(ctx context.Context, vehicleIDs []string) (dbmodels.OnboardingSlice, error) {
	tx, err := r.db.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		r.logger.Error().Err(err).Msg("GetOnboardingsByVins: Failed to begin transaction for vehicles")
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.logger.Error().Err(rbErr).Msgf("GetOnboardingsByVins: Failed to rollback transaction for vehicles")
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				r.logger.Error().Err(cmErr).Msgf("GetOnboardingsByVins: Failed to commit transaction for vehicles")
			}
		}
	}()

	vins, err := dbmodels.Onboardings(dbmodels.OnboardingWhere.Vin.IN(vehicleIDs)).All(ctx, tx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrOnboardingVehicleNotFound
		}
		r.logger.Error().Err(err).Msgf("GetOnboardingsByVins: Failed to check if vehicles have been processed")
		return nil, err
	}

	return vins, nil
}

// GetOnboardingsByVinsAndStatus retrieves vehicles available for minting SD (or vehicle + SD) by their VINs.
func (r *onboardingRepository) GetOnboardingsByVinsAndStatus(ctx context.Context, vehicleIDs []string, status int) (dbmodels.OnboardingSlice, error) {
	tx, err := r.db.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		r.logger.Error().Err(err).Msg("GetOnboardingsByVins: Failed to begin transaction for vehicles")
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.logger.Error().Err(rbErr).Msgf("GetOnboardingsByVins: Failed to rollback transaction for vehicles")
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				r.logger.Error().Err(cmErr).Msgf("GetOnboardingsByVins: Failed to commit transaction for vehicles")
			}
		}
	}()

	vins, err := dbmodels.Onboardings(
		dbmodels.OnboardingWhere.Vin.IN(vehicleIDs),
		dbmodels.OnboardingWhere.OnboardingStatus.EQ(status),
	).All(ctx, tx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrOnboardingVehicleNotFound
		}
		r.logger.Error().Err(err).Msgf("GetOnboardingsByVins: Failed to check if vehicles have been processed")
		return nil, err
	}

	return vins, nil
}

func (r *onboardingRepository) GetOnboardingsByVinsAndStatusRange(ctx context.Context, vehicleIDs []string, minStatus, maxStatus int, additionalStatuses []int) (dbmodels.OnboardingSlice, error) {
	tx, err := r.db.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		r.logger.Error().Err(err).Msg("GetOnboardingsByVins: Failed to begin transaction for vehicles")
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.logger.Error().Err(rbErr).Msgf("GetOnboardingsByVins: Failed to rollback transaction for vehicles")
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				r.logger.Error().Err(cmErr).Msgf("GetOnboardingsByVins: Failed to commit transaction for vehicles")
			}
		}
	}()

	var vins dbmodels.OnboardingSlice

	if len(additionalStatuses) > 0 {
		vinInRange := dbmodels.OnboardingWhere.Vin.IN(vehicleIDs)
		statusInRange := qm.Expr(dbmodels.OnboardingWhere.OnboardingStatus.GTE(minStatus), dbmodels.OnboardingWhere.OnboardingStatus.LTE(maxStatus))
		statusInRangeOrAdditional := qm.Expr(statusInRange, qm.Or2(dbmodels.OnboardingWhere.OnboardingStatus.IN(additionalStatuses)))

		vins, err = dbmodels.Onboardings(
			vinInRange,
			statusInRangeOrAdditional,
		).All(ctx, tx)
	} else {
		vins, err = dbmodels.Onboardings(
			dbmodels.OnboardingWhere.Vin.IN(vehicleIDs),
			dbmodels.OnboardingWhere.OnboardingStatus.GTE(minStatus),
			dbmodels.OnboardingWhere.OnboardingStatus.LTE(maxStatus),
		).All(ctx, tx)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrOnboardingVehicleNotFound
		}
		r.logger.Error().Err(err).Msgf("GetOnboardingsByVinsAndStatusRange: Failed to fetch vehicles")
		return nil, err
	}

	return vins, nil
}

// GetOnboardingByExternalID retrieves a vehicle by its external ID.
func (r *onboardingRepository) GetOnboardingByExternalID(ctx context.Context, externalID string) (*dbmodels.Onboarding, error) {
	tx, err := r.db.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		r.logger.Error().Err(err).Msgf("Failed to begin transaction for external ID %s", externalID)
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.logger.Error().Err(rbErr).Msgf("Failed to rollback transaction for external ID %s", externalID)
			}
		}
	}()

	externalIDNull := null.StringFrom(externalID)
	vin, err := dbmodels.Onboardings(dbmodels.OnboardingWhere.ExternalID.EQ(externalIDNull)).One(ctx, tx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("vehicle not found: " + externalID)
		}
		r.logger.Error().Err(err).Msgf("Failed to check if vehicle with external ID %s has been processed", externalID)
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		r.logger.Error().Err(err).Msgf("Failed to commit transaction for external ID %s", externalID)
		return nil, err
	}

	return vin, nil
}

// InsertOnboarding inserts a new VIN record into the database.
func (r *onboardingRepository) InsertOnboarding(ctx context.Context, vin *dbmodels.Onboarding) error {
	tx, err := r.db.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		r.logger.Error().Err(err).Msgf("Failed to begin transaction for vehicle %s", vin.Vin)
		return err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.logger.Error().Err(rbErr).Msgf("InsertOnboarding: Failed to rollback transaction for vehicle %s", vin.Vin)
			}
		}
	}()

	err = vin.Insert(ctx, tx, boil.Infer())
	if err != nil {
		return fmt.Errorf("failed to insert VIN record: %v", err)
	}

	if err := tx.Commit(); err != nil {
		r.logger.Error().Err(err).Msgf("Failed to commit transaction for vehicle %s", vin.Vin)
		return err
	}

	return nil
}

// InsertOrUpdateOnboarding inserts a new VIN record into the database.
func (r *onboardingRepository) InsertOrUpdateOnboarding(ctx context.Context, vin *dbmodels.Onboarding) error {
	tx, err := r.db.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		r.logger.Error().Err(err).Msgf("Failed to begin transaction for vehicle %s", vin.Vin)
		return err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.logger.Error().Err(rbErr).Msgf("InsertOrUpdateOnboarding: Failed to rollback transaction for vehicle %s", vin.Vin)
			}
		}
	}()

	err = vin.Upsert(ctx, tx, true, []string{"vin"}, boil.Infer(), boil.Infer())
	if err != nil {
		return fmt.Errorf("failed to insert VIN record: %v", err)
	}

	if err := tx.Commit(); err != nil {
		r.logger.Error().Err(err).Msgf("Failed to commit transaction for vehicle %s", vin.Vin)
		return err
	}

	return nil
}

// GetOnboardingsByTokenIDs retrieves VINs where VehicleTokenID is in the provided token IDs.
func (r *onboardingRepository) GetOnboardingsByTokenIDs(ctx context.Context, tokenIDsToCheck []int64) (dbmodels.OnboardingSlice, error) {
	vins, err := dbmodels.Onboardings(dbmodels.OnboardingWhere.VehicleTokenID.IN(tokenIDsToCheck)).All(ctx, r.db.DBS().Reader)
	if err != nil {
		r.logger.Error().Err(err).Msg("Failed to get VINs by token IDs")
		return nil, fmt.Errorf("failed to get VINs by token IDs: %w", err)
	}
	return vins, nil
}

// GetOnboardings retrieves all VINs from the database.
func (r *onboardingRepository) GetOnboardings(ctx context.Context) (dbmodels.OnboardingSlice, error) {
	tx, err := r.db.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		r.logger.Error().Err(err).Msg("Failed to begin transaction")
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil && err == nil {
				r.logger.Error().Err(rbErr).Msg("Failed to rollback transaction")
			}
		}
	}()

	vins, err := dbmodels.Onboardings().All(ctx, tx)
	if err != nil {
		r.logger.Error().Err(err).Msg("Failed to get VINs")
		return nil, fmt.Errorf("failed to get VINs: %w", err)
	}

	if err := tx.Commit(); err != nil {
		r.logger.Error().Err(err).Msg("Failed to commit transaction")
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return vins, nil
}

// DeleteOnboarding deletes onboarding record from DB.
func (r *onboardingRepository) DeleteOnboarding(ctx context.Context, record *dbmodels.Onboarding) error {
	tx, err := r.db.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		r.logger.Error().Err(err).Msgf("Failed to begin transaction for vehicle %s", record.Vin)
		return err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				r.logger.Error().Err(rbErr).Msgf("DeleteOnboarding: Failed to rollback transaction for vehicle %s", record.Vin)
			}
		}
	}()

	_, err = record.Delete(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to delete VIN record: %v", err)
	}

	if err := tx.Commit(); err != nil {
		r.logger.Error().Err(err).Msgf("Failed to commit transaction for vehicle %s", record.Vin)
		return err
	}

	return nil
}

// DeleteAllOnboardings deletes all onboarding records.
func (r *onboardingRepository) DeleteAllOnboardings(ctx context.Context) error {
	tx, err := r.db.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		r.logger.Error().Err(err).Msg("Failed to begin transaction")
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil && err == nil {
				r.logger.Error().Err(rbErr).Msg("Failed to rollback transaction")
			}
		}
	}()

	_, err = dbmodels.Onboardings().DeleteAll(ctx, tx)
	if err != nil {
		r.logger.Error().Err(err).Msg("Failed to delete VINs")
		return fmt.Errorf("failed to delete VINs: %w", err)
	}

	if err := tx.Commit(); err != nil {
		r.logger.Error().Err(err).Msg("Failed to commit transaction")
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
