package service

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/DIMO-Network/go-transactions"
	registry "github.com/DIMO-Network/go-transactions/contracts"
	"github.com/DIMO-Network/go-zerodev"
	"github.com/DIMO-Network/shared/pkg/logfields"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/DIMO-Network/tesla-oracle/pkg/wallet"
	"github.com/aarondl/null/v8"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	signer "github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

var vinRegexp, _ = regexp.Compile("^[A-HJ-NPR-Z0-9]{17}$")

// Onboarding status constants (duplicated to avoid circular dependency)
const (
	OnboardingStatusVendorValidationSuccess = 23
	OnboardingStatusMintFailure             = 52
	OnboardingStatusMintSuccess             = 53
	OnboardingStatusMintSubmitUnknown       = 30
	OnboardingStatusMintSubmitFailure       = 32
	OnboardingStatusMintSubmitPending       = 31
	OnboardingStatusBurnSDSuccess           = 83
	OnboardingStatusBurnVehicleSuccess      = 103
)

// Onboarding status helper functions (duplicated to avoid circular dependency)
func isMinted(status int) bool {
	return status == 53 // OnboardingStatusMintSuccess
}

func isDisconnected(status int) bool {
	return status == OnboardingStatusBurnSDSuccess
}

func isFailure(status int) bool {
	return status%10 == 2
}

func isMintPending(status int) bool {
	return status > OnboardingStatusMintSubmitUnknown && status < 53 // OnboardingStatusMintSuccess
}

func isDisconnectPending(status int) bool {
	return (status > 60 && status < OnboardingStatusBurnSDSuccess) && !isFailure(status) // OnboardingStatusDisconnectSubmitUnknown
}

func getVerificationStatus(status int) string {
	if status >= OnboardingStatusVendorValidationSuccess {
		return "Success"
	}
	if isFailure(status) {
		return "Failure"
	}
	if status > 0 && status < 53 { // OnboardingStatusMintSuccess
		return "Pending"
	}
	return "Unknown"
}

func getMintStatus(status int) string {
	if status == 53 { // OnboardingStatusMintSuccess
		return "Success"
	}
	if isFailure(status) {
		return "Failure"
	}
	if status > 0 && status < 53 { // OnboardingStatusMintSuccess
		return "Pending"
	}
	return "Unknown"
}

func getDetailedStatus(status int) string {
	statusToString := map[int]string{
		32: "MintSubmitFailure",
		31: "MintSubmitPending",
		// Add more as needed
	}
	detailedStatus, ok := statusToString[status]
	if !ok {
		return "Unknown"
	}
	return detailedStatus
}

// ErrTeslaLoginRequired: the caller has no current Tesla login that lists the VIN.
// Onboarding a VIN requires the caller's own Tesla account to see that vehicle.
var ErrTeslaLoginRequired = errors.New("log in to Tesla again to continue")

// DetailsReadyToFinalize is the verify status detail for a VIN whose mint already
// succeeded: the caller skips minting and finalizes.
const DetailsReadyToFinalize = "Ready to finalize"

// OnboardingSacd represents SACD data structure
type OnboardingSacd struct {
	Grantee     common.Address `json:"grantee"`
	Permissions *big.Int       `json:"permissions"`
	Expiration  *big.Int       `json:"expiration"`
	Source      string         `json:"source"`
}

// OnboardingArgs represents job arguments for River. It is the only definition:
// the onboarding worker aliases it, so the options the service inserts with are
// the ones the worker was written for.
type OnboardingArgs struct {
	Owner     common.Address    `json:"owner"`
	VIN       string            `json:"vin"`
	TypedData *signer.TypedData `json:"typedData"`
	Signature hexutil.Bytes     `json:"signature"`
	Sacd      *OnboardingSacd   `json:"sacd,omitempty"`
}

func (OnboardingArgs) Kind() string {
	return "onboard"
}

// InsertOpts makes a mint job run once. A retry after a mint whose transaction
// landed but whose result was lost would mint a second vehicle and SD.
func (OnboardingArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: 1,
		UniqueOpts: river.UniqueOpts{
			ByArgs: false,
		},
	}
}

// VehicleOnboardService handles all business logic for vehicle onboarding operations
type VehicleOnboardService interface {
	VerifyVins(ctx context.Context, vinsData []VinWithTokenID, walletAddress common.Address) ([]VinStatus, error)
	GetMintDataForVins(ctx context.Context, vins []string, ownerAddress common.Address) ([]VinTransactionData, error)
	SubmitMintDataForVins(ctx context.Context, mintingData []VinTransactionData, walletAddress common.Address) ([]VinStatus, error)
	GetMintStatusForVins(ctx context.Context, vins []string) ([]VinStatus, error)
	FinalizeOnboarding(ctx context.Context, vins []string, walletAddress common.Address) ([]OnboardedVehicle, error)
}

type VinWithTokenID struct {
	Vin            string `json:"vin"`
	VehicleTokenID int64  `json:"vehicleTokenId,omitempty"`
}

type VinStatus struct {
	Vin string `json:"vin"`
	// Status `"Pending"`, `"Failure"`, `"Success"`
	Status  string `json:"status"`
	Details string `json:"details"`
}

type SacdInput struct {
	Grantee     common.Address `json:"grantee"`
	Permissions int64          `json:"permissions"`
	Expiration  int64          `json:"expiration"`
	Source      string         `json:"source"`
}

type VinTransactionData struct {
	Vin       string            `json:"vin"`
	TypedData *signer.TypedData `json:"typedData,omitempty"`
	Signature hexutil.Bytes     `json:"signature,omitempty"`
	Sacd      SacdInput         `json:"sacd,omitempty"`
}

type VinUserOperationData struct {
	Vin           string                 `json:"vin"`
	UserOperation *zerodev.UserOperation `json:"userOperation"`
	Hash          common.Hash            `json:"hash"`
	Signature     hexutil.Bytes          `json:"signature,omitempty"`
}

type OnboardedVehicle struct {
	Vin              string   `json:"vin"`
	VehicleTokenID   *big.Int `json:"vehicleTokenId,omitempty" swaggertype:"integer"`
	SyntheticTokenID *big.Int `json:"syntheticTokenId,omitempty" swaggertype:"integer"`
}

type vehicleOnboardService struct {
	settings     *config.Settings
	logger       *zerolog.Logger
	identitySvc  IdentityAPIService
	riverClient  *river.Client[pgx.Tx]
	walletSvc    wallet.SDWalletsAPI
	transactions *transactions.Client
	repositories *repository.Repositories
}

// NewVehicleOnboardService creates a new VehicleOnboardService
func NewVehicleOnboardService(
	settings *config.Settings,
	logger *zerolog.Logger,
	identitySvc IdentityAPIService,
	riverClient *river.Client[pgx.Tx],
	walletSvc wallet.SDWalletsAPI,
	transactions *transactions.Client,
	repositories *repository.Repositories,
) VehicleOnboardService {
	return &vehicleOnboardService{
		settings:     settings,
		logger:       logger,
		identitySvc:  identitySvc,
		riverClient:  riverClient,
		walletSvc:    walletSvc,
		transactions: transactions,
		repositories: repositories,
	}
}

// VerifyVins verifies vehicles before onboarding
func (s *vehicleOnboardService) VerifyVins(ctx context.Context, vinsData []VinWithTokenID, walletAddress common.Address) ([]VinStatus, error) {
	localLog := s.logger.With().Interface("vins", vinsData).Str(logfields.FunctionName, "VerifyVins").Logger()
	localLog.Debug().Msg("Verification for Vins")

	indexedVehicles := make(map[string]VinWithTokenID)
	validVins := make([]string, 0, len(vinsData))

	for _, vehicle := range vinsData {
		strippedVin := strings.TrimSpace(vehicle.Vin)
		if s.isValidVin(strippedVin) {
			validVins = append(validVins, strippedVin)
			indexedVehicles[vehicle.Vin] = vehicle
		}
	}

	if len(validVins) != len(vinsData) {
		return nil, errors.New("Invalid VINs provided")
	}

	compactedVins := slices.Compact(validVins)
	if len(validVins) != len(compactedVins) {
		return nil, errors.New("Duplicated VINs")
	}

	localLog.Debug().Interface("validVins", validVins).Msgf("Got %d valid VINs for get mint", len(validVins))

	statuses := make([]VinStatus, 0, len(validVins))

	if len(validVins) > 0 {
		if _, err := s.requireTeslaLogin(ctx, walletAddress, validVins); err != nil {
			return nil, err
		}

		// Check for reconnection cases - create onboarding records for disconnected devices
		for _, vehicle := range vinsData {
			if vehicle.VehicleTokenID != 0 {
				if err := s.createOnboardingRecordForReconnection(ctx, vehicle, walletAddress); err != nil {
					return nil, err
				}
			}
		}

		// fetch all the onboarding records that could still be moved forward, including
		// minted ones whose finalize never ran
		dbVins, err := s.repositories.Onboarding.GetOnboardingsByVinsAndStatusRange(
			ctx,
			validVins,
			OnboardingStatusVendorValidationSuccess,
			OnboardingStatusMintFailure,
			[]int{OnboardingStatusMintSuccess},
		)
		if err != nil {
			if errors.Is(err, repository.ErrOnboardingVehicleNotFound) {
				return nil, errors.New("could not find vehicles")
			}
			return nil, fmt.Errorf("failed to load vehicles from database: %w", err)
		}

		if len(dbVins) != len(validVins) {
			return nil, errors.New("some of the VINs are not verified or already onboarded")
		}

		indexedVins := make(map[string]*dbmodels.Onboarding)
		for _, vin := range dbVins {
			indexedVins[vin.Vin] = vin
		}

		// we need to do extra checks for provided vehicle token ids
		for _, dbVin := range dbVins {
			vehicle, ok := indexedVehicles[dbVin.Vin]
			if !ok {
				statuses = append(statuses, VinStatus{Vin: vehicle.Vin, Status: "Unknown", Details: "Unknown"})
				continue
			}

			if isMinted(dbVin.OnboardingStatus) {
				// A mint that succeeded but was never finalized: the caller can finish it,
				// if the minted vehicle is theirs and its SD is still the one minted.
				if !s.isResumableMint(dbVin, walletAddress) {
					return nil, errors.New("some of the VINs are not verified or already onboarded")
				}
				statuses = append(statuses, VinStatus{Vin: vehicle.Vin, Status: "Success", Details: DetailsReadyToFinalize})
				continue
			}

			if vehicle.VehicleTokenID != 0 {
				var identityVehicle *models.Vehicle
				identityVehicle, err = s.identitySvc.FetchVehicleByTokenID(vehicle.VehicleTokenID)
				if err == nil && identityVehicle != nil {
					if identityVehicle.Owner != walletAddress.String() {
						// If the provided vehicle token ID is owned by someone else, we need to mint a new one
						identityVehicle = nil
						s.logger.Warn().Msgf(`Vehicle %d is not owned by the wallet %s.`, vehicle.VehicleTokenID, walletAddress.String())
					} else if identityVehicle.SyntheticDevice.TokenID != 0 {
						// If the provided vehicle is already fully minted (has SD), we need to mint a new one
						identityVehicle = nil
						s.logger.Warn().Msgf(`Vehicle %d is already connected.`, vehicle.VehicleTokenID)
					} else if identityVehicle.Definition.ID != dbVin.DeviceDefinitionID.String {
						// If provided vehicle is not the same MMY, we need to mint a new one
						identityVehicle = nil
						s.logger.Warn().Msgf(`Vehicle has incorrect definition: %d`, vehicle.VehicleTokenID)
					} else {
						// Looks legit, let's update onboarding record with the provided vehicle token id
						dbVin.VehicleTokenID = null.Int64From(vehicle.VehicleTokenID)
						err = s.repositories.Onboarding.InsertOrUpdateOnboarding(ctx, dbVin)
						if err != nil {
							s.logger.Error().Msgf(`Failed to set vehicle token ID %d for VIN %s`, vehicle.VehicleTokenID, vehicle.Vin)
							return nil, fmt.Errorf("failed to set vehicle token ID: %w", err)
						}
					}
				}

				if identityVehicle != nil {
					statuses = append(statuses, VinStatus{Vin: vehicle.Vin, Status: "Success", Details: "Ready to mint Synthetic Device"})
				} else {
					statuses = append(statuses, VinStatus{Vin: vehicle.Vin, Status: "Success", Details: "Ready to mint Vehicle and Synthetic Device"})
				}
			} else {
				statuses = append(statuses, VinStatus{Vin: vehicle.Vin, Status: "Success", Details: "Ready to mint Vehicle and Synthetic Device"})
			}
		}
	}

	return statuses, nil
}

// createOnboardingRecordForReconnection creates an onboarding record for a disconnected vehicle that needs reconnection
func (s *vehicleOnboardService) createOnboardingRecordForReconnection(ctx context.Context, vehicle VinWithTokenID, walletAddress common.Address) error {
	localLog := s.logger.With().
		Str("vin", vehicle.Vin).
		Int64("vehicleTokenId", vehicle.VehicleTokenID).
		Str(logfields.FunctionName, "createOnboardingRecordForReconnection").
		Logger()

	// Check if this is a reconnection (disconnected device exists in synthetic_devices).
	// Look it up by vehicle token ID, not VIN: several wallets can mint the same VIN,
	// and a VIN lookup can return another wallet's row.
	disconnectedDevice, err := s.repositories.Vehicle.GetSyntheticDeviceByTokenID(ctx, vehicle.VehicleTokenID)
	isDisconnected := err == nil && disconnectedDevice != nil &&
		disconnectedDevice.Vin == vehicle.Vin &&
		!disconnectedDevice.TokenID.Valid &&
		disconnectedDevice.VehicleTokenID.Valid

	if !isDisconnected {
		// Not a reconnection case, skip
		return nil
	}

	localLog.Info().Msg("Detected reconnection request - creating onboarding record")

	// Fetch vehicle from Identity API to get device definition and verify ownership
	identityVehicle, err := s.identitySvc.FetchVehicleByTokenID(vehicle.VehicleTokenID)
	if err != nil {
		localLog.Error().Err(err).Msg("Failed to fetch vehicle from Identity API")
		return fmt.Errorf("failed to fetch vehicle %d from identity: %w", vehicle.VehicleTokenID, err)
	}

	// Verify ownership
	if identityVehicle.Owner != walletAddress.String() {
		localLog.Warn().
			Str("expectedOwner", walletAddress.String()).
			Str("actualOwner", identityVehicle.Owner).
			Msg("Vehicle not owned by wallet")
		return fmt.Errorf("vehicle %d is not owned by wallet %s", vehicle.VehicleTokenID, walletAddress.String())
	}

	// Verify the vehicle is truly disconnected (no SD minted)
	if identityVehicle.SyntheticDevice.TokenID != 0 {
		// Unless that SD is this reconnection's own mint, not yet finalized: leave
		// the minted record for verify to offer as ready to finalize.
		record, err := s.repositories.Onboarding.GetOnboardingByVin(ctx, vehicle.Vin)
		if err == nil && isMinted(record.OnboardingStatus) &&
			record.VehicleTokenID.Int64 == vehicle.VehicleTokenID &&
			record.SyntheticTokenID.Int64 == identityVehicle.SyntheticDevice.TokenID {
			return nil
		}

		localLog.Warn().
			Int64("syntheticTokenId", identityVehicle.SyntheticDevice.TokenID).
			Msg("Vehicle already has synthetic device connected")
		return fmt.Errorf("vehicle %d is already connected with synthetic device %d", vehicle.VehicleTokenID, identityVehicle.SyntheticDevice.TokenID)
	}

	// Create onboarding record for reconnection. The upsert overwrites every column,
	// so a record left behind by an earlier mint that was never finalized (its SD
	// since burned) loses its stale synthetic token ID and wallet index.
	onboardingRecord := &dbmodels.Onboarding{
		Vin:                vehicle.Vin,
		VehicleTokenID:     null.Int64From(vehicle.VehicleTokenID),
		SyntheticTokenID:   null.Int64{Valid: false}, // NULL - needs minting
		WalletIndex:        null.Int64{Valid: false}, // NULL - the mint allocates a fresh one
		DeviceDefinitionID: null.StringFrom(identityVehicle.Definition.ID),
		OnboardingStatus:   OnboardingStatusVendorValidationSuccess, // 23 - ready to mint
	}

	err = s.repositories.Onboarding.InsertOrUpdateOnboarding(ctx, onboardingRecord)
	if err != nil {
		localLog.Error().Err(err).Msg("Failed to create onboarding record for reconnection")
		return fmt.Errorf("failed to create onboarding record for reconnection: %w", err)
	}

	localLog.Info().
		Str("deviceDefinitionId", identityVehicle.Definition.ID).
		Msg("Successfully created onboarding record for reconnection")

	return nil
}

// GetMintDataForVins gets minting payload for signing
func (s *vehicleOnboardService) GetMintDataForVins(ctx context.Context, vins []string, ownerAddress common.Address) ([]VinTransactionData, error) {
	localLog := s.logger.With().Interface("vins", vins).Str("owner_address", ownerAddress.Hex()).Str(logfields.FunctionName, "GetMintDataForVins").Logger()
	localLog.Debug().Msg("Checking Verification Status for Vins")

	validVins := make([]string, 0, len(vins))
	for _, vin := range vins {
		strippedVin := strings.TrimSpace(vin)
		if s.isValidVin(strippedVin) {
			validVins = append(validVins, strippedVin)
		}
	}

	if len(validVins) != len(vins) {
		return nil, errors.New("Invalid VINs provided")
	}

	compactedVins := slices.Compact(validVins)
	if len(validVins) != len(compactedVins) {
		return nil, errors.New("Duplicated VINs")
	}

	localLog.Debug().Interface("validVins", validVins).Msgf("Got %d valid VINs for get mint", len(validVins))

	mintingData := make([]VinTransactionData, 0, len(validVins))

	if len(validVins) > 0 {
		if _, err := s.requireTeslaLogin(ctx, ownerAddress, validVins); err != nil {
			return nil, err
		}

		dbVins, err := s.repositories.Onboarding.GetOnboardingsByVinsAndStatusRange(
			ctx,
			validVins,
			OnboardingStatusVendorValidationSuccess,
			OnboardingStatusMintFailure,
			[]int{OnboardingStatusBurnSDSuccess, OnboardingStatusBurnVehicleSuccess},
		)
		if err != nil {
			if errors.Is(err, repository.ErrOnboardingVehicleNotFound) {
				return nil, errors.New("could not find vehicles")
			}
			return nil, fmt.Errorf("failed to load vehicles from database: %w", err)
		}

		if len(dbVins) != len(validVins) {
			return nil, errors.New("some of the VINs are not verified or already onboarded")
		}

		for _, dbVin := range dbVins {
			localLog.Debug().Str(logfields.DefinitionID, dbVin.DeviceDefinitionID.String).Msgf("getting definition for vin")
			definition, err := s.identitySvc.GetDeviceDefinitionByID(dbVin.DeviceDefinitionID.String)
			if err != nil {
				return nil, fmt.Errorf("failed to load device definition: %w", err)
			}

			var typedData *signer.TypedData

			if dbVin.VehicleTokenID.IsZero() {
				// Need to mint vehicle first
				typedData = s.transactions.GetMintVehicleWithDDTypedData(
					new(big.Int).SetUint64(definition.Manufacturer.TokenID),
					ownerAddress, // Use actual wallet address from JWT token
					definition.DeviceDefinitionID,
					[]registry.AttributeInfoPair{
						{
							Attribute: "Make",
							Info:      definition.Manufacturer.Name,
						},
						{
							Attribute: "Model",
							Info:      definition.Model,
						},
						{
							Attribute: "Year",
							Info:      strconv.Itoa(definition.Year),
						},
					},
				)
			} else if dbVin.SyntheticTokenID.IsZero() {
				// Need to mint synthetic device
				integrationOrConnectionID, ok := new(big.Int).SetString(s.settings.ConnectionTokenID, 10)
				if !ok {
					return nil, errors.New("failed to set integration or connection token ID")
				}
				typedData = s.transactions.GetMintSDTypedDataV2(integrationOrConnectionID, big.NewInt(dbVin.VehicleTokenID.Int64))
			} else {
				return nil, errors.New("VIN already fully minted and connected or connection in progress")
			}

			vinMintingData := VinTransactionData{
				Vin: dbVin.Vin,
			}

			if typedData != nil {
				vinMintingData.TypedData = typedData
			}

			mintingData = append(mintingData, vinMintingData)
		}
	}

	return mintingData, nil
}

// SubmitMintDataForVins submits signed data and sacd to mint
func (s *vehicleOnboardService) SubmitMintDataForVins(ctx context.Context, mintingData []VinTransactionData, walletAddress common.Address) ([]VinStatus, error) {
	localLog := s.logger.With().Str(logfields.FunctionName, "SubmitMintDataForVins").Logger()
	localLog.Debug().Msg("Submitting VINs to mint")
	localLog.Debug().Interface("params", mintingData).Msg("Got params")

	validVins := make([]string, 0, len(mintingData))
	validVinsMintingData := make([]VinTransactionData, 0, len(mintingData))

	for _, paramVin := range mintingData {
		validatedVinMintingData, err := s.getValidatedMintingData(&paramVin)
		if err != nil {
			return nil, fmt.Errorf("invalid minting data: %w", err)
		}

		validVins = append(validVins, validatedVinMintingData.Vin)
		validVinsMintingData = append(validVinsMintingData, *validatedVinMintingData)
	}

	if len(validVins) != len(mintingData) {
		return nil, errors.New("Invalid minting data provided")
	}

	compactedVins := slices.Compact(validVins)
	if len(validVins) != len(compactedVins) {
		return nil, errors.New("Duplicated VINs")
	}

	localLog.Debug().Interface("validVins", validVins).Msgf("Got %d valid VINs", len(validVins))

	statuses := make([]VinStatus, 0, len(mintingData))

	if len(validVins) > 0 {
		if _, err := s.requireTeslaLogin(ctx, walletAddress, validVins); err != nil {
			return nil, err
		}

		dbVins, err := s.repositories.Onboarding.GetOnboardingsByVins(ctx, validVins)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, errors.New("could not find vehicles")
			}
			return nil, fmt.Errorf("failed to load vehicles from database: %w", err)
		}

		indexedDbVins := make(map[string]*dbmodels.Onboarding)
		for _, vin := range dbVins {
			indexedDbVins[vin.Vin] = vin
		}

		// Every VIN needs the record verify worked with. Creating one here made a
		// record with no device definition: its mint failed, and the record then
		// blocked the VIN for everyone.
		for _, mint := range validVinsMintingData {
			if _, ok := indexedDbVins[mint.Vin]; !ok {
				return nil, fmt.Errorf("VIN %s has not been verified for onboarding", mint.Vin)
			}
		}

		for _, mint := range validVinsMintingData {
			dbVin := indexedDbVins[mint.Vin]

			var sacd *OnboardingSacd

			if mint.Sacd.Expiration != 0 && mint.Sacd.Permissions != 0 {
				sacd = &OnboardingSacd{
					Grantee:     mint.Sacd.Grantee,
					Expiration:  new(big.Int).SetInt64(mint.Sacd.Expiration),
					Permissions: new(big.Int).SetInt64(mint.Sacd.Permissions),
					Source:      mint.Sacd.Source,
				}
			}

			if s.canSubmitMintingJob(dbVin) {
				localLog.Debug().Str(logfields.VIN, mint.Vin).Msg("Submitting minting job")
				_, err = s.riverClient.Insert(ctx, OnboardingArgs{
					VIN:       mint.Vin,
					TypedData: mint.TypedData,
					Signature: mint.Signature,
					Owner:     walletAddress,
					Sacd:      sacd,
				}, nil)

				if err != nil {
					s.logger.Error().Str(logfields.VIN, mint.Vin).Err(err).Msg("Failed to submit minting job")
					statuses = append(statuses, VinStatus{
						Vin:     mint.Vin,
						Status:  "Failure",
						Details: getDetailedStatus(OnboardingStatusMintSubmitFailure),
					})
				} else {
					s.logger.Debug().Str(logfields.VIN, mint.Vin).Msg("minting job submitted")
					statuses = append(statuses, VinStatus{
						Vin:     mint.Vin,
						Status:  "Pending",
						Details: getDetailedStatus(OnboardingStatusMintSubmitPending),
					})
				}
			} else {
				s.logger.Debug().Str(logfields.VIN, mint.Vin).Msg("Skipping minting job submission")
				statuses = append(statuses, VinStatus{
					Vin:     mint.Vin,
					Status:  getVerificationStatus(dbVin.OnboardingStatus),
					Details: getDetailedStatus(dbVin.OnboardingStatus),
				})
			}

			err = s.repositories.Onboarding.InsertOrUpdateOnboarding(ctx, dbVin)
			if err != nil {
				return nil, fmt.Errorf("failed to submit verification for mint: %v: %w", mint, err)
			}
			localLog.Debug().Str(logfields.VIN, mint.Vin).Msg("Submitted mint for VIN")
		}
	}

	return statuses, nil
}

// GetMintStatusForVins gets status of minting jobs for provided VINs
func (s *vehicleOnboardService) GetMintStatusForVins(ctx context.Context, vins []string) ([]VinStatus, error) {
	localLog := s.logger.With().Str(logfields.FunctionName, "GetMintStatusForVins").Interface("validVins", vins).Logger()
	localLog.Debug().Interface("vins", vins).Msg("Checking Verification Status for Vins")

	validVins := make([]string, 0, len(vins))
	for _, vin := range vins {
		strippedVin := strings.TrimSpace(vin)
		if s.isValidVin(strippedVin) {
			validVins = append(validVins, strippedVin)
		}
	}

	if len(validVins) != len(vins) {
		return nil, errors.New("Invalid VINs provided")
	}

	compactedVins := slices.Compact(validVins)
	if len(validVins) != len(compactedVins) {
		return nil, errors.New("Duplicated VINs")
	}

	localLog.Debug().Interface("validVins", validVins).Msgf("Got %d valid VINs", len(validVins))

	statuses := make([]VinStatus, 0, len(validVins))

	if len(validVins) > 0 {
		dbVins, err := s.repositories.Onboarding.GetOnboardingsByVins(ctx, validVins)
		if err != nil {
			if errors.Is(err, repository.ErrOnboardingVehicleNotFound) {
				return nil, errors.New("could not find vehicles")
			}
			return nil, fmt.Errorf("failed to load vehicles from database: %w", err)
		}

		indexedVins := make(map[string]*dbmodels.Onboarding)
		for _, vin := range dbVins {
			indexedVins[vin.Vin] = vin
		}

		for _, vin := range validVins {
			dbVin, ok := indexedVins[vin]
			if !ok {
				statuses = append(statuses, VinStatus{
					Vin:     vin,
					Status:  "Unknown",
					Details: "Unknown",
				})
			} else {
				statuses = append(statuses, VinStatus{
					Vin:     vin,
					Status:  getMintStatus(dbVin.OnboardingStatus),
					Details: getDetailedStatus(dbVin.OnboardingStatus),
				})
			}
		}
	}

	return statuses, nil
}

// FinalizeOnboarding finalizes onboarding process and returns minted token IDs
func (s *vehicleOnboardService) FinalizeOnboarding(ctx context.Context, vins []string, walletAddress common.Address) ([]OnboardedVehicle, error) {
	localLog := s.logger.With().Str(logfields.FunctionName, "FinalizeOnboarding").Interface("validVins", vins).Logger()
	localLog.Debug().Interface("vins", vins).Msg("Checking Verification Status for Vins")

	validVins := make([]string, 0, len(vins))
	for _, vin := range vins {
		strippedVin := strings.TrimSpace(vin)
		if s.isValidVin(strippedVin) {
			validVins = append(validVins, strippedVin)
		}
	}

	if len(validVins) != len(vins) {
		return nil, errors.New("Invalid VINs provided")
	}

	compactedVins := slices.Compact(validVins)
	if len(validVins) != len(compactedVins) {
		return nil, errors.New("Duplicated VINs")
	}

	localLog.Debug().Interface("validVins", validVins).Msgf("Got %d valid VINs", len(validVins))

	vehicles := make([]OnboardedVehicle, 0, len(validVins))

	if len(validVins) == 0 {
		return vehicles, nil
	}

	creds, err := s.requireTeslaLogin(ctx, walletAddress, validVins)
	if err != nil {
		return nil, err
	}

	encryptedCreds, err := s.repositories.Credential.EncryptTokens(creds)
	if err != nil {
		localLog.Error().Err(err).Msg("Failed to encrypt credentials")
		return nil, fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	dbVins, err := s.repositories.Onboarding.GetOnboardingsByVins(ctx, validVins)
	if err != nil {
		if errors.Is(err, repository.ErrOnboardingVehicleNotFound) {
			return nil, errors.New("could not find vehicles")
		}
		return nil, fmt.Errorf("failed to load vehicles from database: %w", err)
	}

	indexedVins := make(map[string]*dbmodels.Onboarding)
	for _, vin := range dbVins {
		indexedVins[vin.Vin] = vin
	}

	for _, vin := range validVins {
		dbVin, ok := indexedVins[vin]
		if !ok {
			return nil, fmt.Errorf("no onboarding in progress for VIN %s", vin)
		}

		if !isMinted(dbVin.OnboardingStatus) || !dbVin.VehicleTokenID.Valid || !dbVin.SyntheticTokenID.Valid || !dbVin.WalletIndex.Valid {
			return nil, fmt.Errorf("VIN %s is not minted yet", vin)
		}

		// The caller's Tesla login goes onto this vehicle's synthetic device, so the
		// vehicle has to be the caller's.
		if err := s.requireMintedToWallet(ctx, dbVin, walletAddress); err != nil {
			return nil, err
		}

		address, err := s.walletSvc.GetAddress(ctx, uint32(dbVin.WalletIndex.Int64))
		if err != nil {
			return nil, fmt.Errorf("failed to get SD address by child index: %w", err)
		}

		sdRecord := &dbmodels.SyntheticDevice{
			Address:            address.Bytes(),
			Vin:                vin,
			TokenID:            null.IntFrom(int(dbVin.SyntheticTokenID.Int64)),
			VehicleTokenID:     null.IntFrom(int(dbVin.VehicleTokenID.Int64)),
			WalletChildNumber:  null.IntFrom(int(dbVin.WalletIndex.Int64)),
			AccessToken:        null.StringFrom(encryptedCreds.AccessToken),
			AccessExpiresAt:    null.TimeFrom(encryptedCreds.AccessExpiry),
			RefreshToken:       null.StringFrom(encryptedCreds.RefreshToken),
			RefreshExpiresAt:   null.TimeFrom(encryptedCreds.RefreshExpiry),
			SubscriptionStatus: null.StringFrom("pending"), // a reconnection keeps its own
		}

		reconnected, err := s.repositories.Vehicle.CompleteOnboarding(ctx, sdRecord, dbVin)
		if err != nil {
			localLog.Error().Err(err).Str(logfields.VIN, vin).Msg("Failed to save the onboarded synthetic device")
			return nil, fmt.Errorf("failed to save synthetic device: %w", err)
		}

		if reconnected {
			localLog.Info().
				Str("vin", vin).
				Int64("vehicleTokenId", dbVin.VehicleTokenID.Int64).
				Int64("newSyntheticTokenId", dbVin.SyntheticTokenID.Int64).
				Msg("Successfully reconnected vehicle with preserved subscription status")
		}

		vehicles = append(vehicles, OnboardedVehicle{
			Vin:              vin,
			VehicleTokenID:   big.NewInt(dbVin.VehicleTokenID.Int64),
			SyntheticTokenID: big.NewInt(dbVin.SyntheticTokenID.Int64),
		})
	}

	// The Tesla login is used up only now that every device is saved: a failure
	// above leaves it for the retry.
	s.repositories.Credential.DeleteIfUnchanged(ctx, walletAddress, creds)

	return vehicles, nil
}

// requireTeslaLogin returns the caller's current Tesla login, if it lists every VIN.
func (s *vehicleOnboardService) requireTeslaLogin(ctx context.Context, walletAddress common.Address, vins []string) (*repository.Credential, error) {
	creds, err := s.repositories.Credential.Retrieve(ctx, walletAddress)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: your Tesla login has expired", ErrTeslaLoginRequired)
		}
		return nil, fmt.Errorf("failed to load Tesla login: %w", err)
	}

	for _, vin := range vins {
		if !slices.Contains(creds.VINs, vin) {
			return nil, fmt.Errorf("%w: VIN %s is not in the Tesla account you logged in with", ErrTeslaLoginRequired, vin)
		}
	}

	return creds, nil
}

// identityWaitAttempts and identityWaitDelay bound how long finalize waits for
// identity-api to index a vehicle minted moments ago. identity-api reads the same
// contract-event topic this service does, which in prod delivers a mint about 10s
// after submit, so 30s leaves room for a slow indexer while staying under the
// ingress's 60s read timeout. A finalize that still times out keeps the Tesla
// login, so the user can press Continue again.
var (
	identityWaitAttempts = 30
	identityWaitDelay    = time.Second
)

// requireMintedToWallet checks the record's minted vehicle belongs to the wallet
// and still carries the record's SD. A just-minted vehicle can take a few seconds
// to reach identity-api, so it waits for it.
func (s *vehicleOnboardService) requireMintedToWallet(ctx context.Context, record *dbmodels.Onboarding, walletAddress common.Address) error {
	for attempt := 1; ; attempt++ {
		vehicle, err := s.identitySvc.FetchVehicleByTokenID(record.VehicleTokenID.Int64)
		if err == nil && vehicle != nil && vehicle.Owner != "" {
			if common.HexToAddress(vehicle.Owner) != walletAddress {
				return fmt.Errorf("vehicle %d is not owned by wallet %s", record.VehicleTokenID.Int64, walletAddress.Hex())
			}
			if sd := vehicle.SyntheticDevice.TokenID; sd != 0 && sd != record.SyntheticTokenID.Int64 {
				return fmt.Errorf("vehicle %d has synthetic device %d, not the minted %d", record.VehicleTokenID.Int64, sd, record.SyntheticTokenID.Int64)
			}
			return nil
		}

		if attempt >= identityWaitAttempts {
			if err == nil {
				err = errors.New("not indexed yet")
			}
			return fmt.Errorf("failed to confirm the owner of vehicle %d: %w", record.VehicleTokenID.Int64, err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(identityWaitDelay):
		}
	}
}

// isResumableMint reports whether a minted, unfinalized record can be finalized by
// the wallet: its vehicle is the wallet's and still carries the minted SD.
func (s *vehicleOnboardService) isResumableMint(record *dbmodels.Onboarding, walletAddress common.Address) bool {
	if !record.VehicleTokenID.Valid || !record.SyntheticTokenID.Valid || !record.WalletIndex.Valid {
		return false
	}
	vehicle, err := s.identitySvc.FetchVehicleByTokenID(record.VehicleTokenID.Int64)
	if err != nil || vehicle == nil || vehicle.Owner == "" {
		return false
	}
	return common.HexToAddress(vehicle.Owner) == walletAddress &&
		vehicle.SyntheticDevice.TokenID == record.SyntheticTokenID.Int64
}

// Helper methods

func (s *vehicleOnboardService) isValidVin(vin string) bool {
	return vinRegexp.MatchString(vin)
}

func (s *vehicleOnboardService) getValidatedMintingData(data *VinTransactionData) (*VinTransactionData, error) {
	result := new(VinTransactionData)

	// Validate VIN
	strippedVin := strings.TrimSpace(data.Vin)
	if !s.isValidVin(strippedVin) {
		return nil, errors.New("invalid VIN")
	}

	// Validate typed data with device definition (if applicable)
	if data.TypedData != nil && data.TypedData.PrimaryType == "MintVehicleWithDeviceDefinitionSign" {
		_, err := s.identitySvc.GetDeviceDefinitionByID(data.TypedData.Message["deviceDefinitionId"].(string))
		if err != nil {
			return nil, err
		}
		// TODO: validate if definition aligns with message data
	}

	result.Vin = strippedVin
	result.TypedData = data.TypedData
	result.Signature = data.Signature
	result.Sacd = data.Sacd
	return result, nil
}

func (s *vehicleOnboardService) canSubmitMintingJob(record *dbmodels.Onboarding) bool {
	if record == nil {
		return false
	}

	minted := isMinted(record.OnboardingStatus)
	burned := isDisconnected(record.OnboardingStatus)
	failed := isFailure(record.OnboardingStatus)
	pending := isMintPending(record.OnboardingStatus) || isDisconnectPending(record.OnboardingStatus)

	// we allow already minted vehicles since minting will be skipped anyway, but all other steps can execute
	return (minted) || (!minted || burned) && (failed || !pending)
}
