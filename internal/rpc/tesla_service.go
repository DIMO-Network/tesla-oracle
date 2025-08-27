package rpc

import (
	"context"
	"fmt"

	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/DIMO-Network/tesla-oracle/pkg/grpc"
	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type WalletProvider interface {
	GetAddress(ctx context.Context, index uint32) (common.Address, error)
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

func isVINChar(c rune) bool {
	// Of course, there is more subtlety to this: disallowed characters, among other things.
	return 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

func (t *TeslaRPCService) RegisterNewSyntheticDeviceV2(ctx context.Context, req *grpc.RegisterNewSyntheticDeviceV2Request) (*grpc.RegisterNewSyntheticDeviceV2Response, error) {
	if len(req.Vin) != 17 {
		return nil, status.Error(codes.InvalidArgument, "VIN does not have length 17")
	}
	for i, c := range req.Vin {
		if !isVINChar(c) {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("VIN has invalid character %q at position %d", c, i))
		}
	}

	var walletIndex int64 // The sequence has the default type, bigint.
	err := t.dbs().Writer.QueryRowContext(ctx, "SELECT nextval('sd_wallet_index_seq')").Scan(&walletIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to get synthetic wallet index: %w", err)
	}

	// For key derivation, the indexes can be in the range [0, 2^31 - 1]. This also,
	// conveniently, means the value fits in an int32, which is what Postgres is using,
	// and such values certainly fit into uint32.
	if walletIndex < 0 || walletIndex >= hdkeychain.HardenedKeyStart {
		return nil, fmt.Errorf("generated wallet index %d is out of bounds", walletIndex)
	}

	walletIndexBounded := uint32(walletIndex)

	sdAddr, err := t.wp.GetAddress(ctx, walletIndexBounded)
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

	t.logger.Info().Str("vin", req.Vin).Str("address", sdAddr.Hex()).Msgf("Provisioning synthetic device for devices-api.")

	return &grpc.RegisterNewSyntheticDeviceV2Response{
		SyntheticDeviceAddress: sdAddr.Bytes(),
		WalletChildNum:         walletIndexBounded,
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
