package service

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/DIMO-Network/go-transactions"
	registry "github.com/DIMO-Network/go-transactions/contracts"
	"github.com/DIMO-Network/go-zerodev"
	"github.com/DIMO-Network/shared/pkg/logfields"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
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

// OnboardingSacd represents SACD data structure
type OnboardingSacd struct {
	Grantee     common.Address `json:"grantee"`
	Permissions *big.Int       `json:"permissions"`
	Expiration  *big.Int       `json:"expiration"`
	Source      string         `json:"source"`
}

// OnboardingArgs represents job arguments for River
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
	walletSvc    SDWalletsAPI
	transactions *transactions.Client
	repositories *repository.Repositories
}

// NewVehicleOnboardService creates a new VehicleOnboardService
func NewVehicleOnboardService(
	settings *config.Settings,
	logger *zerolog.Logger,
	identitySvc IdentityAPIService,
	riverClient *river.Client[pgx.Tx],
	walletSvc SDWalletsAPI,
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
		// fetch all the onboarding records that could still be moved forward
		dbVins, err := s.repositories.Onboarding.GetOnboardingsByVinsAndStatusRange(
			ctx,
			validVins,
			OnboardingStatusVendorValidationSuccess,
			OnboardingStatusMintFailure,
			nil,
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

		for _, mint := range validVinsMintingData {
			dbVin, ok := indexedDbVins[mint.Vin]
			if !ok {
				dbVin = &dbmodels.Onboarding{
					Vin:              mint.Vin,
					OnboardingStatus: OnboardingStatusMintSubmitUnknown,
				}
			}

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

	if len(validVins) > 0 {
		localLog.Debug().Msg("[Finalize Debug] Fetching onboarding records from database")
		dbVins, err := s.repositories.Onboarding.GetOnboardingsByVins(ctx, validVins)
		if err != nil {
			if errors.Is(err, repository.ErrOnboardingVehicleNotFound) {
				localLog.Error().Err(err).Msg("[Finalize Debug] Could not find vehicles in onboarding table")
				return nil, errors.New("could not find vehicles")
			}
			localLog.Error().Err(err).Msg("[Finalize Debug] Failed to load vehicles from database")
			return nil, fmt.Errorf("failed to load vehicles from database: %w", err)
		}

		localLog.Debug().Int("count", len(dbVins)).Msg("[Finalize Debug] Found onboarding records")

		indexedVins := make(map[string]*dbmodels.Onboarding)
		for _, vin := range dbVins {
			indexedVins[vin.Vin] = vin
		}

		for _, vin := range validVins {
			dbVin, ok := indexedVins[vin]
			if !ok {
				localLog.Warn().Str("vin", vin).Msg("[Finalize Debug] VIN not found in indexed vins, skipping")
				continue
			}

			address, err := s.walletSvc.GetAddress(ctx, uint32(dbVin.WalletIndex.Int64))
			if err != nil {
				return nil, fmt.Errorf("failed to get SD address by child index: %w", err)
			}

			creds, err := s.repositories.Credential.RetrieveAndDelete(ctx, walletAddress)
			if err != nil {
				localLog.Error().Err(err).Msg("Failed to retrieve credentials")
				return nil, fmt.Errorf("failed to retrieve credentials: %w", err)
			}

			encryptedCreds, err := s.repositories.Credential.EncryptTokens(creds)
			if err != nil {
				localLog.Error().Err(err).Msg("Failed to encrypt credentials")
				return nil, fmt.Errorf("failed to encrypt credentials: %w", err)
			}

			sdRecord := &dbmodels.SyntheticDevice{
				Address:           address.Bytes(),
				Vin:               vin,
				TokenID:           null.Int{Int: int(dbVin.SyntheticTokenID.Int64), Valid: true},
				VehicleTokenID:    null.Int{Int: int(dbVin.VehicleTokenID.Int64), Valid: true},
				WalletChildNumber: int(dbVin.WalletIndex.Int64),
				AccessToken:       null.StringFrom(encryptedCreds.AccessToken),
				AccessExpiresAt:   null.TimeFrom(encryptedCreds.AccessExpiry),
				RefreshToken:      null.StringFrom(encryptedCreds.RefreshToken),
				RefreshExpiresAt:  null.TimeFrom(encryptedCreds.RefreshExpiry),
			}

			err = s.repositories.Vehicle.InsertSyntheticDevice(ctx, sdRecord)
			if err != nil {
				localLog.Error().Err(err).Msg("Failed to insert Synthetic Device")
				return nil, fmt.Errorf("failed to insert synthetic device: %w", err)
			}

			err = s.repositories.Onboarding.DeleteOnboarding(ctx, dbVin)
			if err != nil {
				localLog.Error().Err(err).Msg("Failed to delete onboarding data from Database")
			}

			vehicles = append(vehicles, OnboardedVehicle{
				Vin:              vin,
				VehicleTokenID:   big.NewInt(dbVin.VehicleTokenID.Int64),
				SyntheticTokenID: big.NewInt(dbVin.SyntheticTokenID.Int64),
			})
		}
	}

	localLog.Info().Int("totalVehicles", len(vehicles)).Interface("vehicles", vehicles).Msg("[Finalize Debug] Finalization complete, returning vehicles")
	return vehicles, nil
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
