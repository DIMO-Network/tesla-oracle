package service

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/DIMO-Network/shared/pkg/db"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/friendsofgo/errors"
	"github.com/rs/zerolog"
)

type OnboardingService struct {
	pdb    *db.Store
	logger *zerolog.Logger
}

var ErrVehicleNotFound = errors.New("vehicle not found")

// NewOnboardingService creates a new instance of OnboardingService.
func NewOnboardingService(pdb *db.Store, logger *zerolog.Logger) *OnboardingService {
	return &OnboardingService{
		pdb:    pdb,
		logger: logger,
	}
}

// GetVehicleByVin retrieves a vehicle by its VIN.
func (ds *OnboardingService) GetVehicleByVin(ctx context.Context, vehicleID string) (*dbmodels.Onboarding, error) {
	tx, err := ds.pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		ds.logger.Error().Err(err).Msgf("Failed to begin transaction for vehicle %s", vehicleID)
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				ds.logger.Error().Err(rbErr).Msgf("GetVehicleByVin: Failed to rollback transaction for vehicle %s", vehicleID)
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				ds.logger.Error().Err(cmErr).Msgf("GetVehicleByVin: Failed to commit transaction for vehicle %s", vehicleID)
			}
		}
	}()

	vin, err := dbmodels.Onboardings(dbmodels.OnboardingWhere.Vin.EQ(vehicleID)).One(ctx, tx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVehicleNotFound
		}
		ds.logger.Error().Err(err).Msgf("Failed to check if vehicle %s has been processed", vehicleID)
		return nil, err
	}

	return vin, nil
}

// GetVehiclesByVins retrieves vehicles by their VINs.
func (ds *OnboardingService) GetVehiclesByVins(ctx context.Context, vehicleIDs []string) (dbmodels.OnboardingSlice, error) {
	tx, err := ds.pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		ds.logger.Error().Err(err).Msg("GetVehiclesByVins: Failed to begin transaction for vehicles")
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				ds.logger.Error().Err(rbErr).Msgf("GetVehiclesByVins: Failed to rollback transaction for vehicles")
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				ds.logger.Error().Err(cmErr).Msgf("GetVehiclesByVins: Failed to commit transaction for vehicles")
			}
		}
	}()

	vins, err := dbmodels.Onboardings(dbmodels.OnboardingWhere.Vin.IN(vehicleIDs)).All(ctx, tx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVehicleNotFound
		}
		ds.logger.Error().Err(err).Msgf("GetVehiclesByVins: Failed to check if vehicles have been processed")
		return nil, err
	}

	return vins, nil
}

// GetMintableVehiclesByVins retrieves vehicles available for minting SD (or vehicle + SD) by their VINs.
func (ds *OnboardingService) GetVehiclesByVinsAndOnboardingStatus(ctx context.Context, vehicleIDs []string, status int) (dbmodels.OnboardingSlice, error) {
	tx, err := ds.pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		ds.logger.Error().Err(err).Msg("GetVehiclesByVins: Failed to begin transaction for vehicles")
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				ds.logger.Error().Err(rbErr).Msgf("GetVehiclesByVins: Failed to rollback transaction for vehicles")
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				ds.logger.Error().Err(cmErr).Msgf("GetVehiclesByVins: Failed to commit transaction for vehicles")
			}
		}
	}()

	vins, err := dbmodels.Onboardings(
		dbmodels.OnboardingWhere.Vin.IN(vehicleIDs),
		dbmodels.OnboardingWhere.OnboardingStatus.EQ(status),
	).All(ctx, tx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVehicleNotFound
		}
		ds.logger.Error().Err(err).Msgf("GetVehiclesByVins: Failed to check if vehicles have been processed")
		return nil, err
	}

	return vins, nil
}

func (ds *OnboardingService) GetVehiclesByVinsAndOnboardingStatusRange(ctx context.Context, vehicleIDs []string, minStatus, maxStatus int, additionalStatuses []int) (dbmodels.OnboardingSlice, error) {
	tx, err := ds.pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		ds.logger.Error().Err(err).Msg("GetVehiclesByVins: Failed to begin transaction for vehicles")
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				ds.logger.Error().Err(rbErr).Msgf("GetVehiclesByVins: Failed to rollback transaction for vehicles")
			}
		} else {
			if cmErr := tx.Commit(); cmErr != nil {
				ds.logger.Error().Err(cmErr).Msgf("GetVehiclesByVins: Failed to commit transaction for vehicles")
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
			return nil, ErrVehicleNotFound
		}
		ds.logger.Error().Err(err).Msgf("GetVehiclesByVinsAndOnboardingStatusRange: Failed to fetch vehicles")
		return nil, err
	}

	return vins, nil
}

// GetVehicleByExternalID retrieves a vehicle by its external ID.
func (ds *OnboardingService) GetVehicleByExternalID(ctx context.Context, externalID string) (*dbmodels.Onboarding, error) {
	tx, err := ds.pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		ds.logger.Error().Err(err).Msgf("Failed to begin transaction for external ID %s", externalID)
		return nil, err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				ds.logger.Error().Err(rbErr).Msgf("Failed to rollback transaction for external ID %s", externalID)
			}
		}
	}()

	externalIDNull := null.StringFrom(externalID)
	vin, err := dbmodels.Onboardings(dbmodels.OnboardingWhere.ExternalID.EQ(externalIDNull)).One(ctx, tx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("vehicle not found: " + externalID)
		}
		ds.logger.Error().Err(err).Msgf("Failed to check if vehicle with external ID %s has been processed", externalID)
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		ds.logger.Error().Err(err).Msgf("Failed to commit transaction for external ID %s", externalID)
		return nil, err
	}

	return vin, nil
}

// InsertVinToDB inserts a new VIN record into the database.
func (ds *OnboardingService) InsertVinToDB(ctx context.Context, vin *dbmodels.Onboarding) error {
	tx, err := ds.pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		ds.logger.Error().Err(err).Msgf("Failed to begin transaction for vehicle %s", vin.Vin)
		return err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				ds.logger.Error().Err(rbErr).Msgf("InsertVinToDB: Failed to rollback transaction for vehicle %s", vin.Vin)
			}
		}
	}()

	err = vin.Insert(ctx, tx, boil.Infer())
	if err != nil {
		return fmt.Errorf("failed to insert VIN record: %v", err)
	}

	if err := tx.Commit(); err != nil {
		ds.logger.Error().Err(err).Msgf("Failed to commit transaction for vehicle %s", vin.Vin)
		return err
	}

	return nil
}

// InsertOrUpdateVin inserts a new VIN record into the database.
func (ds *OnboardingService) InsertOrUpdateVin(ctx context.Context, vin *dbmodels.Onboarding) error {
	tx, err := ds.pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		ds.logger.Error().Err(err).Msgf("Failed to begin transaction for vehicle %s", vin.Vin)
		return err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				ds.logger.Error().Err(rbErr).Msgf("InsertVinToDB: Failed to rollback transaction for vehicle %s", vin.Vin)
			}
		}
	}()

	err = vin.Upsert(ctx, tx, true, []string{"vin"}, boil.Infer(), boil.Infer())
	if err != nil {
		return fmt.Errorf("failed to insert VIN record: %v", err)
	}

	if err := tx.Commit(); err != nil {
		ds.logger.Error().Err(err).Msgf("Failed to commit transaction for vehicle %s", vin.Vin)
		return err
	}

	return nil
}

// GetVinsByTokenIDs retrieves VINs where VehicleTokenID is in the provided token IDs.
func (ds *OnboardingService) GetVinsByTokenIDs(ctx context.Context, tokenIDsToCheck []int64) (dbmodels.OnboardingSlice, error) {
	vins, err := dbmodels.Onboardings(dbmodels.OnboardingWhere.VehicleTokenID.IN(tokenIDsToCheck)).All(ctx, ds.pdb.DBS().Reader)
	if err != nil {
		ds.logger.Error().Err(err).Msg("Failed to get VINs by token IDs")
		return nil, fmt.Errorf("failed to get VINs by token IDs: %w", err)
	}
	return vins, nil
}

// GetVehiclesFromDB retrieves all VINs from the database.
func (ds *OnboardingService) GetVehiclesFromDB(ctx context.Context) (dbmodels.OnboardingSlice, error) {
	tx, err := ds.pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		ds.logger.Error().Err(err).Msg("Failed to begin transaction")
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil && err == nil {
				ds.logger.Error().Err(rbErr).Msg("Failed to rollback transaction")
			}
		}
	}()

	vins, err := dbmodels.Onboardings().All(ctx, tx)
	if err != nil {
		ds.logger.Error().Err(err).Msg("Failed to get VINs")
		return nil, fmt.Errorf("failed to get VINs: %w", err)
	}

	if err := tx.Commit(); err != nil {
		ds.logger.Error().Err(err).Msg("Failed to commit transaction")
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return vins, nil
}

// DeleteOnboarding deletes onboarding record from DB.
func (ds *OnboardingService) DeleteOnboarding(ctx context.Context, record *dbmodels.Onboarding) error {
	tx, err := ds.pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		ds.logger.Error().Err(err).Msgf("Failed to begin transaction for vehicle %s", record.Vin)
		return err
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				ds.logger.Error().Err(rbErr).Msgf("InsertVinToDB: Failed to rollback transaction for vehicle %s", record.Vin)
			}
		}
	}()

	_, err = record.Delete(ctx, tx)
	if err != nil {
		return fmt.Errorf("failed to insert VIN record: %v", err)
	}

	if err := tx.Commit(); err != nil {
		ds.logger.Error().Err(err).Msgf("Failed to commit transaction for vehicle %s", record.Vin)
		return err
	}

	return nil
}

// DeleteAll deletes all onboarding records.
func (ds *OnboardingService) DeleteAll(ctx context.Context) error {
	tx, err := ds.pdb.DBS().Writer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		ds.logger.Error().Err(err).Msg("Failed to begin transaction")
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil && err == nil {
				ds.logger.Error().Err(rbErr).Msg("Failed to rollback transaction")
			}
		}
	}()

	_, err = dbmodels.Onboardings().DeleteAll(ctx, tx)
	if err != nil {
		ds.logger.Error().Err(err).Msg("Failed to delete VINs")
		return fmt.Errorf("failed to delete VINs: %w", err)
	}

	if err := tx.Commit(); err != nil {
		ds.logger.Error().Err(err).Msg("Failed to commit transaction")
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
