package controllers

import (
	"database/sql"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/DIMO-Network/go-transactions"
	registry "github.com/DIMO-Network/go-transactions/contracts"
	"github.com/DIMO-Network/go-zerodev"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/shared/pkg/logfields"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/onboarding"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	signer "github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/pkg/errors"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/boil"
)

var vinRegexp, _ = regexp.Compile("^[A-HJ-NPR-Z0-9]{17}$")

type VehicleController struct {
	settings      *config.Settings
	logger        *zerolog.Logger
	identitySvc   service.IdentityAPIService
	onboardingSvc *service.OnboardingService
	riverClient   *river.Client[pgx.Tx]
	walletSvc     service.SDWalletsAPI
	transactions  *transactions.Client
	pdb           *db.Store
	credentials   CredStore
}

func NewVehicleOnboardController(
	settings *config.Settings,
	logger *zerolog.Logger,
	identitySvc service.IdentityAPIService,
	onboardingSvc *service.OnboardingService,
	riverClient *river.Client[pgx.Tx],
	walletSvc service.SDWalletsAPI,
	transactions *transactions.Client,
	pdb *db.Store,
	credentials CredStore,
) *VehicleController {
	return &VehicleController{
		settings:      settings,
		logger:        logger,
		identitySvc:   identitySvc,
		onboardingSvc: onboardingSvc,
		riverClient:   riverClient,
		walletSvc:     walletSvc,
		transactions:  transactions,
		pdb:           pdb,
		credentials:   credentials,
	}
}

type VinWithTokenID struct {
	Vin            string `json:"vin"`
	VehicleTokenID int64  `json:"vehicleTokenId,omitempty"`
}

type VinsVerifyParams struct {
	Vins []VinWithTokenID `json:"vins" query:"vins"`
}

type VinStatus struct {
	Vin     string `json:"vin"`
	Status  string `json:"status"`
	Details string `json:"details"`
}

type StatusForVinsResponse struct {
	Statuses []VinStatus `json:"statuses"`
}

func (v *VehicleController) VerifyVins(c *fiber.Ctx) error {
	walletAddress := c.Locals("wallet").(common.Address)

	params := new(VinsVerifyParams)
	if err := c.BodyParser(params); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse VINs",
		})
	}
	localLog := v.logger.With().Interface("vins", params.Vins).Str(logfields.FunctionName, "VerifyVins").Logger()
	localLog.Debug().Msg("Verification for Vins")

	indexedVehicles := make(map[string]VinWithTokenID)
	validVins := make([]string, 0, len(params.Vins))
	for _, vehicle := range params.Vins {
		strippedVin := strings.TrimSpace(vehicle.Vin)
		if v.isValidVin(strippedVin) {
			validVins = append(validVins, strippedVin)
			indexedVehicles[vehicle.Vin] = vehicle
		}
	}

	if len(validVins) != len(params.Vins) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid VINs provided",
		})
	}

	compactedVins := slices.Compact(validVins)
	if len(validVins) != len(compactedVins) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Duplicated VINs",
		})
	}

	localLog.Debug().Interface("validVins", validVins).Msgf("Got %d valid VINs for get mint", len(validVins))

	statuses := make([]VinStatus, 0, len(validVins))

	if len(validVins) > 0 {
		dbVins, err := v.onboardingSvc.GetVehiclesByVinsAndOnboardingStatusRange(
			c.Context(),
			validVins,
			onboarding.OnboardingStatusVendorValidationSuccess,
			onboarding.OnboardingStatusMintFailure,
			nil,
		)
		if err != nil {
			if errors.Is(err, service.ErrVehicleNotFound) {
				return fiber.NewError(fiber.StatusBadRequest, "Could not find Vehicles")
			}

			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to load vehicles from Database",
			})
		}

		if len(dbVins) != len(validVins) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Some of the VINs are not verified or already onboarded",
			})
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
			}

			if vehicle.VehicleTokenID != 0 {
				var identityVehicle *models.Vehicle
				identityVehicle, err = v.identitySvc.FetchVehicleByTokenID(vehicle.VehicleTokenID)
				if err == nil && identityVehicle != nil {
					if identityVehicle.Owner != walletAddress.String() {
						// If the provided vehicle token ID is owned by someone else, we need to mint a new one
						identityVehicle = nil
						v.logger.Warn().Msgf(`Vehicle %d is not owned by the wallet %s.`, vehicle.VehicleTokenID, walletAddress.String())
					} else if identityVehicle.SyntheticDevice.TokenID != 0 {
						// If the provided vehicle is already fully minted (has SD), we need to  mint a new one
						identityVehicle = nil
						v.logger.Warn().Msgf(`Vehicle %d is already connected.`, vehicle.VehicleTokenID)
					} else if identityVehicle.Definition.ID != dbVin.DeviceDefinitionID.String {
						// If provided vehicle is not the same MMY, we need to mint a new one
						identityVehicle = nil
						v.logger.Warn().Msgf(`Vehicle has incorrect definition: %d`, vehicle.VehicleTokenID)
					} else {
						// Looks legit, let's update onboarding record with the provided vehicle token id
						dbVin.VehicleTokenID = null.Int64From(vehicle.VehicleTokenID)
						err = v.onboardingSvc.InsertOrUpdateVin(c.Context(), dbVin)
						if err != nil {
							v.logger.Error().Msgf(`Failed to set vehicle token ID %d for VIN %s`, vehicle.VehicleTokenID, vehicle.Vin)
							return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
								"error": "Failed to set vehicle token ID",
							})
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

	return c.JSON(StatusForVinsResponse{
		Statuses: statuses,
	})
}

type VinsGetParams struct {
	Vins []string `json:"vins" query:"vins"`
}

func (v *VehicleController) isValidVin(vin string) bool {
	return vinRegexp.MatchString(vin)
}

func (v *VehicleController) GetMintDataForVins(c *fiber.Ctx) error {
	walletAddress := c.Locals("wallet").(common.Address)

	params := new(VinsGetParams)
	if err := c.QueryParser(params); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse VINs",
		})
	}
	localLog := v.logger.With().Interface("vins", params.Vins).Str(logfields.FunctionName, "GetMintDataForVins").Logger()
	localLog.Debug().Msg("Checking Verification Status for Vins")

	validVins := make([]string, 0, len(params.Vins))
	for _, vin := range params.Vins {
		strippedVin := strings.TrimSpace(vin)
		if v.isValidVin(strippedVin) {
			validVins = append(validVins, strippedVin)
		}
	}

	if len(validVins) != len(params.Vins) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid VINs provided",
		})
	}

	compactedVins := slices.Compact(validVins)
	if len(validVins) != len(compactedVins) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Duplicated VINs",
		})
	}

	localLog.Debug().Interface("validVins", validVins).Msgf("Got %d valid VINs for get mint", len(validVins))

	mintingData := make([]VinTransactionData, 0, len(validVins))

	if len(validVins) > 0 {
		dbVins, err := v.onboardingSvc.GetVehiclesByVinsAndOnboardingStatusRange(
			c.Context(),
			validVins,
			onboarding.OnboardingStatusVendorValidationSuccess,
			onboarding.OnboardingStatusMintFailure,
			[]int{onboarding.OnboardingStatusBurnSDSuccess, onboarding.OnboardingStatusBurnVehicleSuccess},
		)
		if err != nil {
			if errors.Is(err, service.ErrVehicleNotFound) {
				return fiber.NewError(fiber.StatusBadRequest, "Could not find Vehicles")
			}

			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to load vehicles from Database",
			})
		}

		if len(dbVins) != len(validVins) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Some of the VINs are not verified or already onboarded",
			})
		}

		indexedVins := make(map[string]*dbmodels.Onboarding)
		for _, vin := range dbVins {
			indexedVins[vin.Vin] = vin
		}

		for _, dbVin := range dbVins {
			localLog.Debug().Str(logfields.DefinitionID, dbVin.DeviceDefinitionID.String).Msgf("getting definition for vin")
			definition, err := v.identitySvc.GetDeviceDefinitionByID(dbVin.DeviceDefinitionID.String)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to load device definition",
				})
			}

			var typedData *signer.TypedData

			if dbVin.VehicleTokenID.IsZero() {
				typedData = v.transactions.GetMintVehicleWithDDTypedData(
					new(big.Int).SetUint64(definition.Manufacturer.TokenID),
					walletAddress,
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
				integrationOrConnectionID, ok := new(big.Int).SetString(v.settings.ConnectionTokenID, 10)
				typedData = v.transactions.GetMintSDTypedDataV2(integrationOrConnectionID, big.NewInt(dbVin.VehicleTokenID.Int64))

				if !ok {
					v.logger.Error().Err(err).Msg("Failed to set integration or connection token ID")
					return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
						"error": "Failed to set integration or connection token ID",
					})
				}
			} else {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "VIN already fully minted and connected or connection in progress",
				})
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

	return c.JSON(MintDataForVins{
		VinMintingData: mintingData,
	})
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

type MintDataForVins struct {
	VinMintingData []VinTransactionData `json:"vinMintingData"`
}

type VinUserOperationData struct {
	Vin           string                 `json:"vin"`
	UserOperation *zerodev.UserOperation `json:"userOperation"`
	Hash          common.Hash            `json:"hash"`
	Signature     hexutil.Bytes          `json:"signature,omitempty"`
}

type DisconnectDataForVins struct {
	VinDisconnectData []VinUserOperationData `json:"vinDisconnectData"`
}

func (v *VehicleController) SubmitMintDataForVins(c *fiber.Ctx) error {
	walletAddress := c.Locals("wallet").(common.Address)

	params := new(MintDataForVins)
	if err := c.BodyParser(params); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse minting data",
		})
	}

	localLog := v.logger.With().Str(logfields.FunctionName, "SubmitMintDataForVins").Logger()
	localLog.Debug().Msg("Submitting VINs to mint")
	localLog.Debug().Interface("params", params).Msg("Got params")

	validVins := make([]string, 0, len(params.VinMintingData))
	validVinsMintingData := make([]VinTransactionData, 0, len(params.VinMintingData))
	for _, paramVin := range params.VinMintingData {
		validatedVinMintingData, err := v.getValidatedMintingData(&paramVin, walletAddress)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid minting data",
			})
		}

		validVins = append(validVins, validatedVinMintingData.Vin)
		validVinsMintingData = append(validVinsMintingData, *validatedVinMintingData)
	}

	if len(validVins) != len(params.VinMintingData) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid minting data provided",
		})
	}

	compactedVins := slices.Compact(validVins)
	if len(validVins) != len(compactedVins) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Duplicated VINs",
		})
	}

	localLog.Debug().Interface("validVins", validVins).Msgf("Got %d valid VINs", len(validVins))

	statuses := make([]VinStatus, 0, len(params.VinMintingData))

	if len(validVins) > 0 {
		dbVins, err := v.onboardingSvc.GetVehiclesByVins(c.Context(), validVins)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fiber.NewError(fiber.StatusNotFound, "Could not find Vehicles")
			}

			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to load vehicles from Database",
			})
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
					OnboardingStatus: onboarding.OnboardingStatusMintSubmitUnknown,
				}
			}

			var sacd *onboarding.OnboardingSacd

			if mint.Sacd.Expiration != 0 && mint.Sacd.Permissions != 0 {
				sacd = &onboarding.OnboardingSacd{
					Grantee:     mint.Sacd.Grantee,
					Expiration:  new(big.Int).SetInt64(mint.Sacd.Expiration),
					Permissions: new(big.Int).SetInt64(mint.Sacd.Permissions),
					Source:      mint.Sacd.Source,
				}
			}

			if v.canSubmitMintingJob(dbVin) {
				localLog.Debug().Str(logfields.VIN, mint.Vin).Msg("Submitting minting job")
				_, err = v.riverClient.Insert(c.Context(), onboarding.OnboardingArgs{
					VIN:       mint.Vin,
					TypedData: mint.TypedData,
					Signature: mint.Signature,
					Owner:     walletAddress,
					Sacd:      sacd,
				}, nil)

				if err != nil {
					v.logger.Error().Str(logfields.VIN, mint.Vin).Err(err).Msg("Failed to submit minting job")
					statuses = append(statuses, VinStatus{
						Vin:     mint.Vin,
						Status:  "Failure",
						Details: onboarding.GetDetailedStatus(onboarding.OnboardingStatusMintSubmitFailure),
					})
				} else {
					v.logger.Debug().Str(logfields.VIN, mint.Vin).Msg("minting job submitted")
					statuses = append(statuses, VinStatus{
						Vin:     mint.Vin,
						Status:  "Pending",
						Details: onboarding.GetDetailedStatus(onboarding.OnboardingStatusMintSubmitPending),
					})
				}
			} else {
				v.logger.Debug().Str(logfields.VIN, mint.Vin).Msg("Skipping minting job submission")
				statuses = append(statuses, VinStatus{
					Vin:     mint.Vin,
					Status:  onboarding.GetVerificationStatus(dbVin.OnboardingStatus),
					Details: onboarding.GetDetailedStatus(dbVin.OnboardingStatus),
				})
			}

			err = v.onboardingSvc.InsertOrUpdateVin(c.Context(), dbVin)

			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": fmt.Sprintf("Failed to submit verification for mint: %v", mint),
				})
			}
			localLog.Debug().Str(logfields.VIN, mint.Vin).Msg("Submitted mint for VIN")
		}
	}

	return c.JSON(StatusForVinsResponse{
		Statuses: statuses,
	})
}

func (v *VehicleController) getValidatedMintingData(data *VinTransactionData, _ common.Address) (*VinTransactionData, error) {
	result := new(VinTransactionData)

	// Validate VIN
	strippedVin := strings.TrimSpace(data.Vin)
	if !v.isValidVin(strippedVin) {
		return nil, errors.New("invalid VIN")
	}

	// Validate typed data with device definition (if applicable)
	if data.TypedData != nil && data.TypedData.PrimaryType == "MintVehicleWithDeviceDefinitionSign" {
		_, err := v.identitySvc.GetDeviceDefinitionByID(data.TypedData.Message["deviceDefinitionId"].(string))
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

func (v *VehicleController) canSubmitMintingJob(record *dbmodels.Onboarding) bool {
	if record == nil {
		return false
	}

	minted := onboarding.IsMinted(record.OnboardingStatus)
	burned := onboarding.IsDisconnected(record.OnboardingStatus)
	failed := onboarding.IsFailure(record.OnboardingStatus)
	pending := onboarding.IsMintPending(record.OnboardingStatus) || onboarding.IsDisconnectPending(record.OnboardingStatus)

	return (minted) || (!minted || burned) && (failed || !pending)
}

func (v *VehicleController) GetMintStatusForVins(c *fiber.Ctx) error {
	params := new(VinsGetParams)
	if err := c.QueryParser(params); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse VINs",
		})
	}

	localLog := v.logger.With().Str(logfields.FunctionName, "GetMintStatusForVins").Interface("validVins", params.Vins).Logger()
	localLog.Debug().Interface("vins", params.Vins).Msg("Checking Verification Status for Vins")

	validVins := make([]string, 0, len(params.Vins))
	for _, vin := range params.Vins {
		strippedVin := strings.TrimSpace(vin)
		if v.isValidVin(strippedVin) {
			validVins = append(validVins, strippedVin)
		}
	}

	if len(validVins) != len(params.Vins) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid VINs provided",
		})
	}

	compactedVins := slices.Compact(validVins)
	if len(validVins) != len(compactedVins) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Duplicated VINs",
		})
	}

	localLog.Debug().Interface("validVins", validVins).Msgf("Got %d valid VINs", len(validVins))

	statuses := make([]VinStatus, 0, len(validVins))

	if len(validVins) > 0 {
		dbVins, err := v.onboardingSvc.GetVehiclesByVins(c.Context(), validVins)
		if err != nil {
			if errors.Is(err, service.ErrVehicleNotFound) {
				return fiber.NewError(fiber.StatusNotFound, "Could not find Vehicles")
			}

			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to load vehicles from Database",
			})
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
					Status:  onboarding.GetMintStatus(dbVin.OnboardingStatus),
					Details: onboarding.GetDetailedStatus(dbVin.OnboardingStatus),
				})
			}
		}
	}

	return c.JSON(StatusForVinsResponse{
		Statuses: statuses,
	})
}

func (v *VehicleController) ClearOnboardingData(c *fiber.Ctx) error {
	err := v.onboardingSvc.DeleteAll(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete onboarding data from Database",
		})
	}

	return nil
}

type OnboardedVehicle struct {
	Vin              string   `json:"vin"`
	VehicleTokenID   *big.Int `json:"vehicleTokenId,omitempty"`
	SyntheticTokenID *big.Int `json:"syntheticTokenId,omitempty"`
}

type FinalizeResponse struct {
	Vehicles []OnboardedVehicle `json:"vehicles"`
}

func (v *VehicleController) FinalizeOnboarding(c *fiber.Ctx) error {
	walletAddress := c.Locals("wallet").(common.Address)

	params := new(VinsGetParams)
	if err := c.BodyParser(params); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Failed to parse VINs",
		})
	}

	localLog := v.logger.With().Str(logfields.FunctionName, "FinalizeOnboarding").Interface("validVins", params.Vins).Logger()
	localLog.Debug().Interface("vins", params.Vins).Msg("Checking Verification Status for Vins")

	validVins := make([]string, 0, len(params.Vins))
	for _, vin := range params.Vins {
		strippedVin := strings.TrimSpace(vin)
		if v.isValidVin(strippedVin) {
			validVins = append(validVins, strippedVin)
		}
	}

	if len(validVins) != len(params.Vins) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid VINs provided",
		})
	}

	compactedVins := slices.Compact(validVins)
	if len(validVins) != len(compactedVins) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Duplicated VINs",
		})
	}

	localLog.Debug().Interface("validVins", validVins).Msgf("Got %d valid VINs", len(validVins))

	vehicles := make([]OnboardedVehicle, 0, len(validVins))

	if len(validVins) > 0 {
		dbVins, err := v.onboardingSvc.GetVehiclesByVins(c.Context(), validVins)
		if err != nil {
			if errors.Is(err, service.ErrVehicleNotFound) {
				return fiber.NewError(fiber.StatusNotFound, "Could not find Vehicles")
			}

			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to load vehicles from Database",
			})
		}

		indexedVins := make(map[string]*dbmodels.Onboarding)
		for _, vin := range dbVins {
			indexedVins[vin.Vin] = vin
		}

		for _, vin := range validVins {
			dbVin, ok := indexedVins[vin]
			if !ok {
				continue
			} else {
				address, err := v.walletSvc.GetAddress(uint32(dbVin.WalletIndex.Int64))
				if err != nil {
					return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
						"error": "Failed to get SD address by child index",
					})
				}

				creds, err := v.credentials.RetrieveWithTokensEncrypted(c.Context(), walletAddress)
				if err != nil {
					localLog.Error().Err(err).Msg("Failed to retrieve credentials")
					return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
						"error": "Failed to retrieve credentials",
					})
				}

				sdRecord := &dbmodels.SyntheticDevice{
					Address:           address.Bytes(),
					Vin:               vin,
					TokenID:           null.Int{Int: int(dbVin.SyntheticTokenID.Int64), Valid: true},
					VehicleTokenID:    null.Int{Int: int(dbVin.VehicleTokenID.Int64), Valid: true},
					WalletChildNumber: int(dbVin.WalletIndex.Int64),
					AccessToken:       null.StringFrom(creds.AccessToken),
					AccessExpiresAt:   null.TimeFrom(creds.AccessExpiry),
					RefreshToken:      null.StringFrom(creds.RefreshToken),
					RefreshExpiresAt:  null.TimeFrom(creds.RefreshExpiry),
				}

				errIns := sdRecord.Insert(c.Context(), v.pdb.DBS().Writer, boil.Infer())
				if errIns != nil {
					localLog.Error().Err(errIns).Msg("Failed to insert Synthetic Device")
					return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
						"error": "Failed to insert Synthetic Device",
					})
				}

				err = v.onboardingSvc.DeleteOnboarding(c.Context(), dbVin)
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
	}

	return c.JSON(FinalizeResponse{
		Vehicles: vehicles,
	})
}
