package rpc

import (
	"context"

	"github.com/DIMO-Network/shared/db"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/DIMO-Network/tesla-oracle/pkg/grpc"
	"github.com/rs/zerolog"
	"github.com/volatiletech/sqlboiler/v4/boil"
)

func NewTeslaRPCService(
	dbs func() *db.ReaderWriter,
	logger *zerolog.Logger,
) grpc.TeslaOracleServer {
	return &TeslaRPCService{
		dbs:    dbs,
		logger: logger,
	}
}

// TeslaRPCService is the grpc server implementation for the proto services
type TeslaRPCService struct {
	grpc.UnimplementedTeslaOracleServer
	dbs      func() *db.ReaderWriter
	settings *config.Settings
	logger   *zerolog.Logger
}

func (t *TeslaRPCService) RegisterNewDevice(ctx context.Context, req *grpc.RegisterNewSyntheticDeviceRequest) (*grpc.RegisterNewSyntheticDeviceResponse, error) {
	partial := models.SyntheticDevice{
		Vin:               req.Vin,
		Address:           req.SyntheticDeviceAddress,
		WalletChildNumber: int(req.GetWalletChildNum()),
	}

	if err := partial.Insert(
		ctx,
		t.dbs().Writer,
		boil.Whitelist(models.SyntheticDeviceColumns.Vin, models.SyntheticDeviceColumns.Address, models.SyntheticDeviceColumns.WalletChildNumber),
	); err != nil {
		return nil, err
	}

	return &grpc.RegisterNewSyntheticDeviceResponse{
		Success: true,
	}, nil
}

func (t *TeslaRPCService) GetVehicleByVIN(ctx context.Context, req *grpc.GetVehicleByVINRequest) (*grpc.GetVehicleByVINResponse, error) {
	devices, err := models.SyntheticDevices(
		models.SyntheticDeviceWhere.Vin.EQ(req.GetVin()),
		models.SyntheticDeviceWhere.VehicleTokenID.IsNotNull(),
		models.SyntheticDeviceWhere.TokenID.IsNotNull(),
	).All(ctx, t.dbs().Reader)
	if err != nil {
		return nil, err
	}

	var all []*grpc.Vehicle
	for _, dev := range devices {
		all = append(
			all,
			&grpc.Vehicle{
				Vin:                    dev.Vin,
				SyntheticDeviceAddress: dev.Address,
				WalletChildNum:         uint64(dev.WalletChildNumber),
				TokenId:                uint64(dev.VehicleTokenID.Int),
				SyntheticTokenId:       uint64(dev.TokenID.Int),
			},
		)
	}

	return &grpc.GetVehicleByVINResponse{
		Devices: all,
	}, nil
}
