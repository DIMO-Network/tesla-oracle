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
	"github.com/DIMO-Network/shared/pkg/logfields"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
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
)

var vinRegexp, _ = regexp.Compile("^[A-HJ-NPR-Z0-9]{17}$")

type VehicleController struct {
	settings    *config.Settings
	logger      *zerolog.Logger
	identity    service.IdentityAPIService
	vs          *service.Vehicle
	riverClient *river.Client[pgx.Tx]
	ws          service.SDWalletsAPI
	tr          *transactions.Client
}

func NewVehicleOnboardController(settings *config.Settings, logger *zerolog.Logger, identity service.IdentityAPIService, vs *service.Vehicle, riverClient *river.Client[pgx.Tx], ws service.SDWalletsAPI, tr *transactions.Client) *VehicleController {
	return &VehicleController{
		settings:    settings,
		logger:      logger,
		identity:    identity,
		vs:          vs,
		riverClient: riverClient,
		ws:          ws,
		tr:          tr,
	}
}

type VinsGetParams struct {
	Vins []string `json:"vins" query:"vins"`
}

func (v *VehicleController) isValidVin(vin string) bool {
	return vinRegexp.MatchString(vin)
}

type VinStatus struct {
	Vin     string `json:"vin"`
	Status  string `json:"status"`
	Details string `json:"details"`
}

type StatusForVinsResponse struct {
	Statuses []VinStatus `json:"statuses"`
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
		dbVins, err := v.vs.GetVehiclesByVinsAndOnboardingStatusRange(
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
			definition, err := v.identity.GetDeviceDefinitionByID(dbVin.DeviceDefinitionID.String)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to load device definition",
				})
			}

			var typedData *signer.TypedData

			if dbVin.VehicleTokenID.IsZero() {
				typedData = v.tr.GetMintVehicleWithDDTypedData(
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
				typedData = v.tr.GetMintSDTypedDataV2(integrationOrConnectionID, big.NewInt(dbVin.VehicleTokenID.Int64))

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
	Grantee     common.Address
	Permissions int64
	Expiration  int64
	Source      string
}
type VinTransactionData struct {
	Vin       string            `json:"vin"`
	TypedData *signer.TypedData `json:"typedData,omitempty"`
	Signature hexutil.Bytes     `json:"signature,omitempty"`
}

type MintDataForVins struct {
	VinMintingData []VinTransactionData `json:"vinMintingData"`
	Sacd           SacdInput            `json:"sacd,omitempty"`
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
		dbVins, err := v.vs.GetVehiclesByVins(c.Context(), validVins)
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

			if params.Sacd.Expiration != 0 && params.Sacd.Permissions != 0 {
				sacd = &onboarding.OnboardingSacd{
					Grantee:     params.Sacd.Grantee,
					Expiration:  new(big.Int).SetInt64(params.Sacd.Expiration),
					Permissions: new(big.Int).SetInt64(params.Sacd.Permissions),
					Source:      params.Sacd.Source,
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

			err = v.vs.InsertOrUpdateVin(c.Context(), dbVin)

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
		_, err := v.identity.GetDeviceDefinitionByID(data.TypedData.Message["deviceDefinitionId"].(string))
		if err != nil {
			return nil, err
		}

		// TODO: validate if definition aligns with message data
	}

	result.Vin = strippedVin
	result.TypedData = data.TypedData
	result.Signature = data.Signature
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
		dbVins, err := v.vs.GetVehiclesByVins(c.Context(), validVins)
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
