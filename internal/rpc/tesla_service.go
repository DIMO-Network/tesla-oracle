package rpc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/DIMO-Network/tesla-oracle/pkg/grpc"
	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type WalletProvider interface {
	GetAddress(ctx context.Context, index uint32) (common.Address, error)
}

func NewTeslaRPCService(
	dbs func() *db.ReaderWriter,
	logger *zerolog.Logger,
	wp WalletProvider,
	lookup service.SyntheticDeviceLookupService,
	vehicles repository.VehicleRepository,
	tokenManager *core.TeslaTokenManager,
	fleetAPI core.TeslaFleetAPIService,
) grpc.TeslaOracleServer {
	return &TeslaRPCService{
		dbs:          dbs,
		logger:       logger,
		wp:           wp,
		lookup:       lookup,
		vehicles:     vehicles,
		tokenManager: tokenManager,
		fleetAPI:     fleetAPI,
	}
}

// TeslaRPCService is the grpc server implementation for the proto services
type TeslaRPCService struct {
	grpc.UnimplementedTeslaOracleServer
	dbs          func() *db.ReaderWriter
	wp           WalletProvider
	logger       *zerolog.Logger
	lookup       service.SyntheticDeviceLookupService
	vehicles     repository.VehicleRepository
	tokenManager *core.TeslaTokenManager
	fleetAPI     core.TeslaFleetAPIService
}

func (t *TeslaRPCService) RegisterNewSyntheticDevice(ctx context.Context, req *grpc.RegisterNewSyntheticDeviceRequest) (*grpc.RegisterNewSyntheticDeviceResponse, error) {
	partial := models.SyntheticDevice{
		Vin:               req.Vin,
		Address:           req.SyntheticDeviceAddress,
		WalletChildNumber: null.IntFrom(int(req.GetWalletChildNum())),
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
		WalletChildNumber: null.IntFrom(int(walletIndex)),
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
	devices, err := t.lookup.GetSyntheticDevicesByVIN(ctx, req.GetVin())
	if err != nil {
		return nil, err
	}

	var all []*grpc.SyntheticDevice
	for _, dev := range devices {
		all = append(
			all,
			&grpc.SyntheticDevice{
				Vin:                dev.VIN,
				Address:            dev.Address,
				WalletChildNum:     dev.WalletChildNum,
				VehicleTokenId:     dev.VehicleTokenID,
				TokenId:            dev.TokenID,
				SubscriptionStatus: dev.SubscriptionStatus,
			},
		)
	}

	return &grpc.GetSyntheticDevicesByVINResponse{
		SyntheticDevices: all,
	}, nil
}

func (t *TeslaRPCService) GetVinByTokenId(ctx context.Context, req *grpc.GetVinByTokenIdRequest) (*grpc.GetVinByTokenIdResponse, error) {
	sd, err := models.SyntheticDevices(
		models.SyntheticDeviceWhere.TokenID.EQ(null.IntFrom(int(req.TokenId))),
	).One(ctx, t.dbs().Reader)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "No known synthetic device with that token id.")
		}
		return nil, err
	}

	return &grpc.GetVinByTokenIdResponse{Vin: sd.Vin}, nil
}

func (t *TeslaRPCService) GetFleetStatusByTokenId(ctx context.Context, req *grpc.GetFleetStatusByTokenIdRequest) (*grpc.GetFleetStatusByTokenIdResponse, error) {
	if req.GetVehicleTokenId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "vehicle_token_id is required")
	}

	sd, err := t.vehicles.GetSyntheticDeviceByTokenID(ctx, int64(req.GetVehicleTokenId()))
	if err != nil {
		if errors.Is(err, repository.ErrVehicleNotFound) || errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "vehicle not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to load vehicle: %v", err)
	}

	if sd == nil || sd.AccessToken.String == "" || sd.RefreshToken.String == "" {
		return nil, status.Error(codes.FailedPrecondition, "no Tesla credentials found for vehicle")
	}

	accessToken, err := t.tokenManager.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrNoCredentials), errors.Is(err, core.ErrTokenExpired):
			return nil, status.Errorf(codes.FailedPrecondition, "Tesla credentials unavailable: %v", err)
		case errors.Is(err, core.ErrCredentialDecryption):
			return nil, status.Errorf(codes.Internal, "failed to decrypt Tesla credentials: %v", err)
		default:
			return nil, status.Errorf(codes.Unavailable, "failed to acquire Tesla access token: %v", err)
		}
	}

	fleetStatus, err := t.fleetAPI.VirtualKeyConnectionStatus(ctx, accessToken, sd.Vin)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to fetch Tesla fleet status: %v", err)
	}

	resp := &grpc.GetFleetStatusByTokenIdResponse{
		KeyPaired:                      fleetStatus.KeyPaired,
		VehicleCommandProtocolRequired: fleetStatus.VehicleCommandProtocolRequired,
		FirmwareVersion:                fleetStatus.FirmwareVersion,
		DiscountedDeviceData:           fleetStatus.DiscountedDeviceData,
		FleetTelemetryVersion:          fleetStatus.FleetTelemetryVersion,
		NumberOfKeys:                   uint32(fleetStatus.NumberOfKeys),
	}
	if fleetStatus.SafetyScreenStreamingToggleEnabled != nil {
		resp.SafetyScreenStreamingToggleEnabled = wrapperspb.Bool(*fleetStatus.SafetyScreenStreamingToggleEnabled)
	}

	return resp, nil
}

func (t *TeslaRPCService) WakeUpCar(ctx context.Context, req *grpc.WakeUpCarRequest) (*grpc.WakeUpCarResponse, error) {
	if req.GetVehicleTokenId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "vehicle_token_id is required")
	}

	sd, err := t.vehicles.GetSyntheticDeviceByTokenID(ctx, int64(req.GetVehicleTokenId()))
	if err != nil {
		if errors.Is(err, repository.ErrVehicleNotFound) || errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "vehicle not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to load vehicle: %v", err)
	}

	if sd == nil || sd.AccessToken.String == "" || sd.RefreshToken.String == "" {
		return nil, status.Error(codes.FailedPrecondition, "no Tesla credentials found for vehicle")
	}

	accessToken, err := t.tokenManager.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrNoCredentials), errors.Is(err, core.ErrTokenExpired):
			return nil, status.Errorf(codes.FailedPrecondition, "Tesla credentials unavailable: %v", err)
		case errors.Is(err, core.ErrCredentialDecryption):
			return nil, status.Errorf(codes.Internal, "failed to decrypt Tesla credentials: %v", err)
		default:
			return nil, status.Errorf(codes.Unavailable, "failed to acquire Tesla access token: %v", err)
		}
	}

	vehicle, err := t.fleetAPI.WakeUpVehicle(ctx, accessToken, sd.Vin)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to wake up vehicle: %v", err)
	}

	return &grpc.WakeUpCarResponse{State: vehicle.State}, nil
}

func (t *TeslaRPCService) GetFleetTelemetryConfigByTokenId(ctx context.Context, req *grpc.GetFleetTelemetryConfigByTokenIdRequest) (*grpc.GetFleetTelemetryConfigByTokenIdResponse, error) {
	if req.GetVehicleTokenId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "vehicle_token_id is required")
	}

	sd, err := t.vehicles.GetSyntheticDeviceByTokenID(ctx, int64(req.GetVehicleTokenId()))
	if err != nil {
		if errors.Is(err, repository.ErrVehicleNotFound) || errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "vehicle not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to load vehicle: %v", err)
	}

	if sd == nil || sd.AccessToken.String == "" || sd.RefreshToken.String == "" {
		return nil, status.Error(codes.FailedPrecondition, "no Tesla credentials found for vehicle")
	}

	accessToken, err := t.tokenManager.GetOrRefreshAccessToken(ctx, sd)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrNoCredentials), errors.Is(err, core.ErrTokenExpired):
			return nil, status.Errorf(codes.FailedPrecondition, "Tesla credentials unavailable: %v", err)
		case errors.Is(err, core.ErrCredentialDecryption):
			return nil, status.Errorf(codes.Internal, "failed to decrypt Tesla credentials: %v", err)
		default:
			return nil, status.Errorf(codes.Unavailable, "failed to acquire Tesla access token: %v", err)
		}
	}

	telemetryStatus, err := t.fleetAPI.GetTelemetrySubscriptionStatus(ctx, accessToken, sd.Vin)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to fetch Tesla fleet telemetry config: %v", err)
	}

	var teslaResponse *structpb.Struct
	if telemetryStatus.Response != nil {
		teslaResponse, err = structpb.NewStruct(telemetryStatus.Response)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to marshal Tesla fleet telemetry config response: %v", err)
		}
	}

	return &grpc.GetFleetTelemetryConfigByTokenIdResponse{
		Synced:        telemetryStatus.Synced,
		Configured:    telemetryStatus.Configured,
		LimitReached:  telemetryStatus.LimitReached,
		KeyPaired:     telemetryStatus.KeyPaired,
		TeslaResponse: teslaResponse,
	}, nil
}
