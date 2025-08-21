package rpc

import (
	"context"
	"fmt"

	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/DIMO-Network/tesla-oracle/pkg/grpc"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"github.com/volatiletech/sqlboiler/v4/queries"
)

type WalletProvider interface {
	GetAddress(index uint32) (common.Address, error)
}

func NewTeslaRPCService(
	dbs func() *db.ReaderWriter,
	logger *zerolog.Logger,
	wp WalletProvider,
) grpc.TeslaOracleServer {
	return &TeslaRPCService{
		dbs:    dbs,
		logger: logger,
		wp:     wp,
	}
}

// TeslaRPCService is the grpc server implementation for the proto services
type TeslaRPCService struct {
	grpc.UnimplementedTeslaOracleServer
	dbs    func() *db.ReaderWriter
	wp     WalletProvider
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

func (t *TeslaRPCService) RegisterNewSyntheticDeviceV2(ctx context.Context, req *grpc.RegisterNewSyntheticDeviceV2Request) (*grpc.RegisterNewSyntheticDeviceV2Response, error) {
	var walletIndex int64
	err := queries.Raw("SELECT nextval(sd_wallet_index_seq)").Bind(ctx, t.dbs().Reader, &walletIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to get synthetic wallet index: %w", err)
	}

	// For key derivation, the indexes can be in the range [0, 2^31 - 1]. This also,
	// conveniently, means the value fits in an int32, which is what Postgres is using;
	// and such values certainly fit into uint32.
	if walletIndex < 0 || walletIndex >= hdkeychain.HardenedKeyStart {
		return nil, fmt.Errorf("generated wallet index %d is out of bounds", walletIndex)
	}

	sdAddr, err := t.wp.GetAddress(uint32(walletIndex))
	if err != nil {
		return nil, fmt.Errorf("failed to construct synthetic wallet from index: %w", err)
	}

	sd := models.SyntheticDevice{
		Address:           sdAddr.Bytes(),
		Vin:               req.Vin,
		WalletChildNumber: int(walletIndex),
		AccessToken:       null.StringFrom(req.EncryptedAccessToken),
		RefreshToken:      null.StringFrom(req.EncryptedRefreshToken),
		AccessExpiresAt:   null.TimeFrom(req.AccessTokenExpiry.AsTime()),
		RefreshExpiresAt:  null.TimeFrom(req.RefreshTokenExpiry.AsTime()),
	}

	err = sd.Insert(ctx, t.dbs().Writer, boil.Infer())
	if err != nil {
		return nil, fmt.Errorf("couldn't insert synthetic device record: %w", err)
	}

	return &grpc.RegisterNewSyntheticDeviceV2Response{
		SyntheticDeviceAddress: sdAddr.Bytes(),
		WalletChildNum:         uint64(walletIndex),
	}, nil
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
				Vin:                dev.Vin,
				Address:            dev.Address,
				WalletChildNum:     uint64(dev.WalletChildNumber),
				VehicleTokenId:     uint64(dev.VehicleTokenID.Int),
				TokenId:            uint64(dev.TokenID.Int),
				SubscriptionStatus: dev.SubscriptionStatus.String,
			},
		)
	}

	return &grpc.GetSyntheticDevicesByVINResponse{
		SyntheticDevices: all,
	}, nil
}
