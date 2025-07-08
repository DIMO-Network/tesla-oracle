package rpc

import (
	"context"

	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/DIMO-Network/tesla-oracle/pkg/grpc"
	"github.com/ethereum/go-ethereum/common"
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
	dbs    func() *db.ReaderWriter
	logger *zerolog.Logger
}

func (t *TeslaRPCService) RegisterNewSyntheticDevice(ctx context.Context, req *grpc.RegisterNewSyntheticDeviceRequest) (*grpc.RegisterNewSyntheticDeviceResponse, error) {
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

	t.logger.Info().Str("vin", req.Vin).Str("address", common.BytesToAddress(req.SyntheticDeviceAddress).Hex()).Msg("registered new device")

	return &grpc.RegisterNewSyntheticDeviceResponse{}, nil
}

func (t *TeslaRPCService) GetSyntheticDevicesByVIN(ctx context.Context, req *grpc.GetSyntheticDevicesByVINRequest) (*grpc.GetSyntheticDevicesByVINResponse, error) {
	devices, err := models.SyntheticDevices(
		models.SyntheticDeviceWhere.Vin.EQ(req.GetVin()),
		models.SyntheticDeviceWhere.VehicleTokenID.IsNotNull(),
		models.SyntheticDeviceWhere.TokenID.IsNotNull(),
	).All(ctx, t.dbs().Reader)
	if err != nil {
		return nil, err
	}

	var all []*grpc.SyntheticDevice
	for _, dev := range devices {
		all = append(
			all,
			&grpc.SyntheticDevice{
				Vin:            dev.Vin,
				Address:        dev.Address,
				WalletChildNum: uint64(dev.WalletChildNumber),
				VehicleTokenId: uint64(dev.VehicleTokenID.Int),
				TokenId:        uint64(dev.TokenID.Int),
			},
		)
	}

	return &grpc.GetSyntheticDevicesByVINResponse{
		SyntheticDevices: all,
	}, nil
}
