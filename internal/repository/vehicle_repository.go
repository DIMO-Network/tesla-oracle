package repository

import (
	"context"
	"database/sql"
	"github.com/DIMO-Network/tesla-oracle/internal/service"

	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/aarondl/sqlboiler/v4/queries/qm"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

type vehicleRepository struct {
	db *db.Store
}

func NewVehicleRepository(db *db.Store) VehicleRepository {
	return &vehicleRepository{db: db}
}

func (r *vehicleRepository) GetVehicleByTokenID(ctx context.Context, tokenID int) (*service.TeslaVehicle, error) {
	vehicle, err := dbmodels.TeslaVehicles(
		qm.Where("token_id = ?", tokenID),
	).One(ctx, r.db.DBS().Reader)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to get vehicle by token ID")
	}

	return vehicle, nil
}

func (r *vehicleRepository) GetVehicleByVIN(ctx context.Context, vin string) (*dbmodels.TeslaVehicle, error) {
	vehicle, err := dbmodels.TeslaVehicles(
		qm.Where("vin = ?", vin),
	).One(ctx, r.db.DBS().Reader)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "failed to get vehicle by VIN")
	}

	return vehicle, nil
}

func (r *vehicleRepository) CreateVehicle(ctx context.Context, vehicle *dbmodels.TeslaVehicle) error {
	if err := vehicle.Insert(ctx, r.db.DBS().Writer, boil.Infer()); err != nil {
		return errors.Wrap(err, "failed to create tesla vehicle")
	}
	return nil
}

func (r *vehicleRepository) UpdateVehicle(ctx context.Context, vehicle *dbmodels.TeslaVehicle) error {
	if _, err := vehicle.Update(ctx, r.db.DBS().Writer, boil.Infer()); err != nil {
		return errors.Wrap(err, "failed to update tesla vehicle")
	}
	return nil
}

func (r *vehicleRepository) CreateOrUpdateVehicle(ctx context.Context, vehicle *dbmodels.TeslaVehicle) error {
	existing, err := r.GetVehicleByVIN(ctx, vehicle.Vin)
	if err != nil {
		return err
	}

	if existing == nil {
		return r.CreateVehicle(ctx, vehicle)
	}

	vehicle.ID = existing.ID
	return r.UpdateVehicle(ctx, vehicle)
}

func (r *vehicleRepository) GetUserVehicles(ctx context.Context, userAddress common.Address) ([]*dbmodels.TeslaVehicle, error) {
	vehicles, err := dbmodels.TeslaVehicles(
		qm.Where("owner_address = ?", userAddress.Hex()),
	).All(ctx, r.db.DBS().Reader)

	if err != nil {
		return nil, errors.Wrap(err, "failed to get user vehicles")
	}

	return vehicles, nil
}

func (r *vehicleRepository) GetVehiclesForMinting(ctx context.Context, vins []string, userAddr common.Address) ([]*dbmodels.TeslaVehicle, error) {
	vehicles, err := dbmodels.TeslaVehicles(
		qm.WhereIn("vin IN ?", vins),
		qm.Where("owner_address = ?", userAddr.Hex()),
	).All(ctx, r.db.DBS().Reader)

	if err != nil {
		return nil, errors.Wrap(err, "failed to get vehicles for minting")
	}

	return vehicles, nil
}
