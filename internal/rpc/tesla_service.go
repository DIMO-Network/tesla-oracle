package rpc

import (
	"context"

	"github.com/DIMO-Network/shared/db"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/DIMO-Network/tesla-oracle/pkg/grpc"
	"github.com/ericlagergren/decimal"
	"github.com/rs/zerolog"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/types"
	"google.golang.org/protobuf/types/known/emptypb"
)

func NewTeslaRPCService(
	dbs func() *db.ReaderWriter,
	settings *config.Settings,
	logger *zerolog.Logger,
) grpc.TeslaOracleServer {
	return &TeslaRPCService{
		dbs:      dbs,
		logger:   logger,
		settings: settings,
	}
}

// TeslaRPCService is the grpc server implementation for the proto services
type TeslaRPCService struct {
	grpc.UnimplementedTeslaOracleServer
	dbs      func() *db.ReaderWriter
	settings *config.Settings
	logger   *zerolog.Logger
}

func (t *TeslaRPCService) RegisterNewDevice(ctx context.Context, req *grpc.RegisterNewDeviceRequest) (*emptypb.Empty, error) {
	walletChildNum := types.NewDecimal(decimal.New(int64(req.WalletChildNum), 0))

	partial := models.Device{
		Vin:                    req.Vin,
		SyntheticDeviceAddress: req.SyntheticDeviceAddress,
		WalletChildNum:         walletChildNum,
	}

	if err := partial.Insert(
		ctx,
		t.dbs().Writer,
		boil.Whitelist(models.DeviceColumns.Vin, models.DeviceColumns.SyntheticDeviceAddress, models.DeviceColumns.WalletChildNum),
	); err != nil {
		return nil, err
	}

	return nil, nil
}

func (t *TeslaRPCService) GetDevicesByVIN(ctx context.Context, req *grpc.GetDevicesByVINRequest) (*grpc.GetDevicesByVINResponse, error) {
	devices, err := models.Devices(
		models.DeviceWhere.Vin.EQ(req.Vin),
		models.DeviceWhere.TokenID.IsNotNull(),
		models.DeviceWhere.SyntheticTokenID.IsNotNull(),
	).All(ctx, t.dbs().Reader)
	if err != nil {
		return nil, err
	}

	var all []*grpc.Device
	for _, dev := range devices {
		walletChildNum, _ := dev.WalletChildNum.Uint64()
		tokenID, _ := dev.TokenID.Uint64()
		syntheticTokenID, _ := dev.SyntheticTokenID.Uint64()

		all = append(
			all,
			&grpc.Device{
				Vin:                    dev.Vin,
				SyntheticDeviceAddress: dev.SyntheticDeviceAddress,
				WalletChildNum:         walletChildNum,
				TokenId:                tokenID,
				SyntheticTokenId:       syntheticTokenID,
			},
		)
	}

	return &grpc.GetDevicesByVINResponse{
		Devices: all,
	}, nil
}
