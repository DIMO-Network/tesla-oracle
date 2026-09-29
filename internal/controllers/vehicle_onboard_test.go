package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/DIMO-Network/tesla-oracle/pkg/wallet"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/helpers"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/test"
	mods "github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"gotest.tools/v3/assert"
)

const ownerAdd = "0x1234567890AbcdEF1234567890aBcdef12345678"
const owner2Add = "0x1234567890AbcdEF1234567890aBcdef12345679"
const sdWalletsSeed = "cabaabd8c7c7d27347349e48fb11319bc6656cb6cc1bdc717e94dae8db7e6bc2"

type VehicleControllerTestSuite struct {
	suite.Suite
	pdb       db.Store
	container testcontainers.Container
	ctx       context.Context
	river     *river.Client[pgx.Tx]
	settings  config.Settings
	ws        *wallet.SDWalletsService
	logger    zerolog.Logger
}

// SetupSuite starts container db
func (s *VehicleControllerTestSuite) SetupSuite() {
	s.ctx = context.Background()
	s.logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	s.pdb, s.container, s.settings = test.StartContainerDatabase(context.Background(), s.T(), migrationsDirRelPath)
	s.ws = wallet.NewSDWalletsService(s.logger, sdWalletsSeed)

	fmt.Println("Suite setup completed.")
}

// TearDownTest after each test truncate tables
func (s *VehicleControllerTestSuite) TearDownTest() {
	fmt.Println("Truncating database ...")
	test.TruncateTables(s.pdb.DBS().Writer.DB, s.T())
}

// TearDownSuite cleanup at end by terminating container
func (s *VehicleControllerTestSuite) TearDownSuite() {
	fmt.Printf("shutting down postgres at with session: %s \n", s.container.SessionID())
	if err := s.container.Terminate(s.ctx); err != nil {
		s.T().Fatal(err)
	}

	fmt.Println("Suite teardown completed.")
}

func TestVehicleControllerTestSuite(t *testing.T) {
	suite.Run(t, new(VehicleControllerTestSuite))
}

type deps struct {
	logger     zerolog.Logger
	identity   service.IdentityAPIService
	credsStore repository.CredentialRepository
}

const vehicleTokenIDnoSDValidDD = 100
const vehicleTokenIDnoSDValidDDDifferentOwner = 110
const vehicleTokenIDwithSDValidDD = 120

const vehicleTokenIDwithSDOtherOwner = 140
const sdTokenIDOtherOwner = 445
const sdTokenIDFinalize = 456

const vehicleTokenIDnoSDInvalidDD = 200
const vehicleTokenIDwithSDInvalidDD = 220

func createMockDependencies(_ *testing.T) deps {
	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "tesla-oracle").
		Logger()

	identity := new(test.MockIdentityAPIService)

	mockVehicleNoSDValidDD := &mods.Vehicle{
		Owner:   ownerAdd,
		TokenID: vehicleTokenIDnoSDValidDD,
		Definition: mods.Definition{
			ID: "test-dd-2025",
		},
	}
	identity.On("FetchVehicleByTokenID", int64(vehicleTokenIDnoSDValidDD)).Return(mockVehicleNoSDValidDD, nil)

	mockVehicleNoSDValidDDDifferentOwner := &mods.Vehicle{
		Owner:   owner2Add,
		TokenID: vehicleTokenIDnoSDValidDDDifferentOwner,
		Definition: mods.Definition{
			ID: "test-dd-2025",
		},
	}
	identity.On("FetchVehicleByTokenID", int64(vehicleTokenIDnoSDValidDDDifferentOwner)).Return(mockVehicleNoSDValidDDDifferentOwner, nil)

	mockVehicleNoSDInvalidDD := &mods.Vehicle{
		Owner:   ownerAdd,
		TokenID: vehicleTokenIDnoSDInvalidDD,
		Definition: mods.Definition{
			ID: "test-dd-2023",
		},
	}
	identity.On("FetchVehicleByTokenID", int64(vehicleTokenIDnoSDInvalidDD)).Return(mockVehicleNoSDInvalidDD, nil)

	mockVehicleWithSDValidDD := &mods.Vehicle{
		Owner:   ownerAdd,
		TokenID: vehicleTokenIDwithSDValidDD,
		SyntheticDevice: mods.SyntheticDevice{
			TokenID: 444,
		},
		Definition: mods.Definition{
			ID: "test-dd-2025",
		},
	}
	identity.On("FetchVehicleByTokenID", int64(vehicleTokenIDwithSDValidDD)).Return(mockVehicleWithSDValidDD, nil)

	mockVehicleWithSDInvalidDD := &mods.Vehicle{
		Owner:   ownerAdd,
		TokenID: vehicleTokenIDwithSDInvalidDD,
		SyntheticDevice: mods.SyntheticDevice{
			TokenID: 444,
		},
		Definition: mods.Definition{
			ID: "test-dd-2023",
		},
	}
	identity.On("FetchVehicleByTokenID", int64(vehicleTokenIDwithSDInvalidDD)).Return(mockVehicleWithSDInvalidDD, nil)

	identity.On("FetchVehicleByTokenID", int64(vehicleTokenIDwithSDOtherOwner)).Return(&mods.Vehicle{
		Owner:           owner2Add,
		TokenID:         vehicleTokenIDwithSDOtherOwner,
		SyntheticDevice: mods.SyntheticDevice{TokenID: sdTokenIDOtherOwner},
		Definition:      mods.Definition{ID: "test-dd-2025"},
	}, nil)

	identity.On("FetchVehicleByTokenID", int64(vehicleTokenID)).Return(&mods.Vehicle{
		Owner:           ownerAdd,
		TokenID:         vehicleTokenID,
		SyntheticDevice: mods.SyntheticDevice{TokenID: sdTokenIDFinalize},
		Definition:      mods.Definition{ID: "test-dd-2025"},
	}, nil)

	credsStore := new(test.MockCredStore)

	return deps{
		logger:     logger,
		identity:   identity,
		credsStore: credsStore,
	}
}

// storeTeslaLogin stands in for POST /v1/vehicles: the caller logged in to Tesla,
// and Tesla listed these VINs.
func storeTeslaLogin(t *testing.T, store repository.CredentialRepository, user string, vins ...string) *repository.Credential {
	creds := &repository.Credential{
		AccessToken:   "access_token",
		RefreshToken:  "refresh_token",
		AccessExpiry:  time.Now().Add(time.Hour),
		RefreshExpiry: time.Now().Add(24 * time.Hour),
		VINs:          vins,
	}
	require.NoError(t, store.Store(context.Background(), common.HexToAddress(user), creds))
	return creds
}

func (s *VehicleControllerTestSuite) TestVerifyVins() {
	t := s.T()
	mockDeps := createMockDependencies(t)

	credStore := repository.NewTempCredsStore(new(cipher.ROT13Cipher))
	storeTeslaLogin(t, credStore, ownerAdd, "ABCDEFG1234567811", "ABCDEFG1234567812", "ABCDEFG1234567813")

	// Create repositories struct
	vehicleRepo := repository.NewVehicleRepository(&s.pdb, new(cipher.ROT13Cipher), &mockDeps.logger)
	onboardingRepo := repository.NewOnboardingRepository(&s.pdb, &mockDeps.logger)
	repos := &repository.Repositories{
		Vehicle:    vehicleRepo,
		Credential: credStore,
		Onboarding: onboardingRepo,
	}

	// Create a mock service for testing
	mockService := service.NewVehicleOnboardService(
		&config.Settings{},
		&mockDeps.logger,
		mockDeps.identity,
		s.river,
		s.ws,
		nil, // transactions client
		repos,
	)

	c := NewVehicleOnboardController(
		&mockDeps.logger,
		mockService,
	)
	app := fiber.New(fiber.Config{
		EnableSplittingOnParsers: true,
	})

	app.Use(func(c *fiber.Ctx) error {
		// Simulate JWT middleware setting the user in Locals
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": ownerAdd,
		})
		c.Locals("user", token)
		return c.Next()
	})
	app.Use(helpers.NewWalletMiddleware())

	app.Post("/vehicle/verify", c.VerifyVins)

	s.Run("Get verification status for empty VIN list", func() {
		payloadJSON, err := json.Marshal(VinsVerifyParams{
			Vins: []service.VinWithTokenID{},
		})
		assert.NilError(t, err)

		req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))
		assert.NilError(s.T(), test.GenerateJWT(req))

		response, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, response.StatusCode)

		body, _ := io.ReadAll(response.Body)
		expected := StatusForVinsResponse{
			Statuses: []service.VinStatus{},
		}

		expectedJSON, err := json.Marshal(expected)
		assert.NilError(t, err)

		assert.Equal(t, string(body), string(expectedJSON))
	})

	s.Run("Get verification status for a list of valid, but unknown VINs", func() {
		payloadJSON, err := json.Marshal(VinsVerifyParams{
			Vins: []service.VinWithTokenID{
				{Vin: "ABCDEFG1234567811"},
				{Vin: "ABCDEFG1234567812", VehicleTokenID: 123},
			},
		})
		assert.NilError(t, err)

		req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))
		assert.NilError(s.T(), test.GenerateJWT(req))

		response, _ := app.Test(req)
		assert.Equal(t, fiber.StatusBadRequest, response.StatusCode)
	})

	s.Run("Fails for duplicates", func() {
		payloadJSON, err := json.Marshal(VinsVerifyParams{
			Vins: []service.VinWithTokenID{
				{Vin: "ABCDEFG1234567811"},
				{Vin: "ABCDEFG1234567811", VehicleTokenID: 123},
			},
		})
		assert.NilError(t, err)

		req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))
		assert.NilError(s.T(), test.GenerateJWT(req))

		response, _ := app.Test(req)
		assert.Equal(t, fiber.StatusBadRequest, response.StatusCode)
	})

	dbVin := dbmodels.Onboarding{
		Vin:                "ABCDEFG1234567812",
		OnboardingStatus:   23, // OnboardingStatusVendorValidationSuccess
		DeviceDefinitionID: null.StringFrom("test-dd-2025"),
	}

	s.Run("Get verification status for a list of valid VINs, some known, some not", func() {
		require.NoError(t, dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

		payloadJSON, err := json.Marshal(VinsVerifyParams{
			Vins: []service.VinWithTokenID{
				{Vin: "ABCDEFG1234567811"},
				{Vin: "ABCDEFG1234567812"},
			},
		})
		assert.NilError(t, err)

		req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))
		assert.NilError(s.T(), test.GenerateJWT(req))

		response, _ := app.Test(req)
		assert.Equal(t, fiber.StatusBadRequest, response.StatusCode)

		_, err = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
		assert.NilError(t, err)
	})

	s.Run("Does not return known VINs when they're not specified", func() {
		require.NoError(t, dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

		payloadJSON, err := json.Marshal(VinsVerifyParams{
			Vins: []service.VinWithTokenID{
				{Vin: "ABCDEFG1234567811"},
			},
		})
		assert.NilError(t, err)

		req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))
		assert.NilError(s.T(), test.GenerateJWT(req))

		response, _ := app.Test(req)
		assert.Equal(t, fiber.StatusBadRequest, response.StatusCode)

		_, err = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
		assert.NilError(t, err)
	})

	s.Run("Properly handles case without vehicle token ID", func() {
		require.NoError(t, dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

		payloadJSON, err := json.Marshal(VinsVerifyParams{
			Vins: []service.VinWithTokenID{
				{Vin: "ABCDEFG1234567812"},
			},
		})
		assert.NilError(t, err)

		req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))
		assert.NilError(s.T(), test.GenerateJWT(req))

		response, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, response.StatusCode)

		body, _ := io.ReadAll(response.Body)
		expected := StatusForVinsResponse{
			Statuses: []service.VinStatus{
				{
					Vin:     "ABCDEFG1234567812",
					Status:  "Success",
					Details: "Ready to mint Vehicle and Synthetic Device",
				},
			},
		}

		expectedJSON, err := json.Marshal(expected)
		assert.NilError(t, err)

		assert.Equal(t, string(body), string(expectedJSON))

		_, err = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
		assert.NilError(t, err)
	})

	s.Run("Properly handles case with a valid vehicle token ID and proper DD, no SD", func() {
		require.NoError(t, dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

		payloadJSON, err := json.Marshal(VinsVerifyParams{
			Vins: []service.VinWithTokenID{
				{Vin: "ABCDEFG1234567812", VehicleTokenID: vehicleTokenIDnoSDValidDD},
			},
		})
		assert.NilError(t, err)

		req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))
		assert.NilError(s.T(), test.GenerateJWT(req))

		response, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, response.StatusCode)

		body, _ := io.ReadAll(response.Body)
		expected := StatusForVinsResponse{
			Statuses: []service.VinStatus{
				{
					Vin:     "ABCDEFG1234567812",
					Status:  "Success",
					Details: "Ready to mint Synthetic Device",
				},
			},
		}

		expectedJSON, err := json.Marshal(expected)
		assert.NilError(t, err)

		assert.Equal(t, string(body), string(expectedJSON))

		_, err = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
		assert.NilError(t, err)
	})

	s.Run("Ignore token ID on valid vehicle token ID, but different owner - full mint", func() {
		require.NoError(t, dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

		payloadJSON, err := json.Marshal(VinsVerifyParams{
			Vins: []service.VinWithTokenID{
				{Vin: "ABCDEFG1234567812", VehicleTokenID: vehicleTokenIDnoSDValidDDDifferentOwner},
			},
		})
		assert.NilError(t, err)

		req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))
		assert.NilError(s.T(), test.GenerateJWT(req))

		response, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, response.StatusCode)

		body, _ := io.ReadAll(response.Body)
		expected := StatusForVinsResponse{
			Statuses: []service.VinStatus{
				{
					Vin:     "ABCDEFG1234567812",
					Status:  "Success",
					Details: "Ready to mint Vehicle and Synthetic Device",
				},
			},
		}

		expectedJSON, err := json.Marshal(expected)
		assert.NilError(t, err)

		assert.Equal(t, string(body), string(expectedJSON))

		_, err = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
		assert.NilError(t, err)
	})

	s.Run("Ignore token ID on valid vehicle token ID, but different DD - full mint", func() {
		require.NoError(t, dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

		payloadJSON, err := json.Marshal(VinsVerifyParams{
			Vins: []service.VinWithTokenID{
				{Vin: "ABCDEFG1234567812", VehicleTokenID: vehicleTokenIDnoSDInvalidDD},
			},
		})
		assert.NilError(t, err)

		req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))
		assert.NilError(s.T(), test.GenerateJWT(req))

		response, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, response.StatusCode)

		body, _ := io.ReadAll(response.Body)
		expected := StatusForVinsResponse{
			Statuses: []service.VinStatus{
				{
					Vin:     "ABCDEFG1234567812",
					Status:  "Success",
					Details: "Ready to mint Vehicle and Synthetic Device",
				},
			},
		}

		expectedJSON, err := json.Marshal(expected)
		assert.NilError(t, err)

		assert.Equal(t, string(body), string(expectedJSON))

		_, err = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
		assert.NilError(t, err)
	})

	s.Run("Ignore token ID on valid vehicle token ID, but already minted SD - full mint", func() {
		require.NoError(t, dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

		payloadJSON, err := json.Marshal(VinsVerifyParams{
			Vins: []service.VinWithTokenID{
				{Vin: "ABCDEFG1234567812", VehicleTokenID: vehicleTokenIDwithSDValidDD},
			},
		})
		assert.NilError(t, err)

		req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))
		assert.NilError(s.T(), test.GenerateJWT(req))

		response, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, response.StatusCode)

		body, _ := io.ReadAll(response.Body)
		expected := StatusForVinsResponse{
			Statuses: []service.VinStatus{
				{
					Vin:     "ABCDEFG1234567812",
					Status:  "Success",
					Details: "Ready to mint Vehicle and Synthetic Device",
				},
			},
		}

		expectedJSON, err := json.Marshal(expected)
		assert.NilError(t, err)

		assert.Equal(t, string(body), string(expectedJSON))

		_, err = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
		assert.NilError(t, err)
	})

	// The same VIN can be minted by several wallets, so synthetic_devices can hold
	// another wallet's connected row next to the caller's disconnected one.
	// Reconnection has to find the caller's row by vehicle token ID, not by VIN.
	sharedVin := "ABCDEFG1234567813"
	for _, tc := range []struct {
		name            string
		stuckOnboarding bool
	}{
		{name: "no onboarding record"},
		{name: "onboarding record stuck after a burned SD", stuckOnboarding: true},
	} {
		s.Run("Reconnects a disconnected vehicle whose VIN another wallet also minted: "+tc.name, func() {
			t := s.T()
			t.Cleanup(func() {
				_, err := dbmodels.Onboardings(dbmodels.OnboardingWhere.Vin.EQ(sharedVin)).DeleteAll(s.ctx, s.pdb.DBS().Writer)
				assert.NilError(t, err)
				_, err = dbmodels.SyntheticDevices(dbmodels.SyntheticDeviceWhere.Vin.EQ(sharedVin)).DeleteAll(s.ctx, s.pdb.DBS().Writer)
				assert.NilError(t, err)
			})

			otherWalletDevice := dbmodels.SyntheticDevice{
				Address:            common.HexToAddress("0x00000000000000000000000000000000000000a1").Bytes(),
				Vin:                sharedVin,
				WalletChildNumber:  null.IntFrom(11),
				VehicleTokenID:     null.IntFrom(130),
				TokenID:            null.IntFrom(555),
				SubscriptionStatus: null.StringFrom("active"),
			}
			require.NoError(t, otherWalletDevice.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

			disconnectedDevice := dbmodels.SyntheticDevice{
				Address:            common.HexToAddress("0x00000000000000000000000000000000000000a2").Bytes(),
				Vin:                sharedVin,
				VehicleTokenID:     null.IntFrom(vehicleTokenIDnoSDValidDD),
				SubscriptionStatus: null.StringFrom("pending"),
			}
			require.NoError(t, disconnectedDevice.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

			if tc.stuckOnboarding {
				// A mint that succeeded but was never finalized, and whose SD was burned since.
				stuck := dbmodels.Onboarding{
					Vin:                sharedVin,
					VehicleTokenID:     null.Int64From(vehicleTokenIDnoSDValidDD),
					SyntheticTokenID:   null.Int64From(169178),
					WalletIndex:        null.Int64From(170171),
					OnboardingStatus:   53, // OnboardingStatusMintSuccess
					DeviceDefinitionID: null.StringFrom("test-dd-2025"),
				}
				require.NoError(t, stuck.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
			}

			payloadJSON, err := json.Marshal(VinsVerifyParams{
				Vins: []service.VinWithTokenID{
					{Vin: sharedVin, VehicleTokenID: vehicleTokenIDnoSDValidDD},
				},
			})
			assert.NilError(t, err)

			req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))
			assert.NilError(s.T(), test.GenerateJWT(req))

			response, _ := app.Test(req)
			body, _ := io.ReadAll(response.Body)
			assert.Equal(t, fiber.StatusOK, response.StatusCode, string(body))

			expectedJSON, err := json.Marshal(StatusForVinsResponse{
				Statuses: []service.VinStatus{
					{
						Vin:     sharedVin,
						Status:  "Success",
						Details: "Ready to mint Synthetic Device",
					},
				},
			})
			assert.NilError(t, err)
			assert.Equal(t, string(body), string(expectedJSON))

			record, err := dbmodels.FindOnboarding(s.ctx, s.pdb.DBS().Reader, sharedVin)
			require.NoError(t, err)
			assert.Equal(t, 23, record.OnboardingStatus) // OnboardingStatusVendorValidationSuccess
			assert.Equal(t, int64(vehicleTokenIDnoSDValidDD), record.VehicleTokenID.Int64)
			assert.Assert(t, !record.SyntheticTokenID.Valid, "stale synthetic token ID kept")
			assert.Assert(t, !record.WalletIndex.Valid, "stale wallet index kept")
		})
	}

	s.Run("Rejects a VIN the caller's Tesla login didn't list", func() {
		t := s.T()
		// Someone else's car, mid-onboarding: its record is there, but the caller's
		// Tesla account can't see it.
		otherVin := dbmodels.Onboarding{
			Vin:                "ABCDEFG1234567899",
			OnboardingStatus:   23, // OnboardingStatusVendorValidationSuccess
			DeviceDefinitionID: null.StringFrom("test-dd-2025"),
		}
		require.NoError(t, otherVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
		t.Cleanup(func() { _, _ = otherVin.Delete(s.ctx, s.pdb.DBS().Writer) })

		payloadJSON, err := json.Marshal(VinsVerifyParams{Vins: []service.VinWithTokenID{{Vin: "ABCDEFG1234567899"}}})
		assert.NilError(t, err)
		req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))

		response, _ := app.Test(req)
		body, _ := io.ReadAll(response.Body)
		assert.Equal(t, fiber.StatusForbidden, response.StatusCode, string(body))
		assert.Assert(t, strings.Contains(string(body), "log in to Tesla again"), string(body))
	})

	s.Run("Rejects every VIN once the Tesla login has expired", func() {
		t := s.T()
		creds, err := credStore.RetrieveAndDelete(s.ctx, common.HexToAddress(ownerAdd))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, credStore.Store(s.ctx, common.HexToAddress(ownerAdd), creds)) })

		require.NoError(t, dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
		t.Cleanup(func() { _, _ = dbVin.Delete(s.ctx, s.pdb.DBS().Writer) })

		payloadJSON, err := json.Marshal(VinsVerifyParams{Vins: []service.VinWithTokenID{{Vin: "ABCDEFG1234567812"}}})
		assert.NilError(t, err)
		response, _ := app.Test(test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON)))
		assert.Equal(t, fiber.StatusForbidden, response.StatusCode)
	})

	// A mint that succeeded but whose finalize never ran (Tesla login expired, the
	// page gave up polling) left its record at MintSuccess, which verify used to
	// refuse forever. The caller can now pick it up and finalize.
	s.Run("Resumes a minted onboarding that was never finalized", func() {
		t := s.T()
		minted := dbmodels.Onboarding{
			Vin:                "ABCDEFG1234567812",
			VehicleTokenID:     null.Int64From(vehicleTokenIDwithSDValidDD),
			SyntheticTokenID:   null.Int64From(444),
			WalletIndex:        null.Int64From(7),
			OnboardingStatus:   53, // OnboardingStatusMintSuccess
			DeviceDefinitionID: null.StringFrom("test-dd-2025"),
		}
		require.NoError(t, minted.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
		t.Cleanup(func() { _, _ = minted.Delete(s.ctx, s.pdb.DBS().Writer) })

		for _, vehicle := range []service.VinWithTokenID{
			{Vin: "ABCDEFG1234567812"},
			{Vin: "ABCDEFG1234567812", VehicleTokenID: vehicleTokenIDwithSDValidDD},
		} {
			payloadJSON, err := json.Marshal(VinsVerifyParams{Vins: []service.VinWithTokenID{vehicle}})
			assert.NilError(t, err)
			response, _ := app.Test(test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON)))
			body, _ := io.ReadAll(response.Body)
			assert.Equal(t, fiber.StatusOK, response.StatusCode, string(body))

			expectedJSON, err := json.Marshal(StatusForVinsResponse{Statuses: []service.VinStatus{
				{Vin: "ABCDEFG1234567812", Status: "Success", Details: service.DetailsReadyToFinalize},
			}})
			assert.NilError(t, err)
			assert.Equal(t, string(body), string(expectedJSON))
		}
	})

	// A reconnect whose SD was minted but never finalized: the vehicle's row is
	// still disconnected, and identity already shows the new SD.
	s.Run("Resumes an unfinalized reconnection", func() {
		t := s.T()
		disconnected := dbmodels.SyntheticDevice{
			Address:            common.HexToAddress("0x00000000000000000000000000000000000000a3").Bytes(),
			Vin:                "ABCDEFG1234567813",
			VehicleTokenID:     null.IntFrom(vehicleTokenIDwithSDValidDD),
			SubscriptionStatus: null.StringFrom("active"),
		}
		require.NoError(t, disconnected.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
		minted := dbmodels.Onboarding{
			Vin:                "ABCDEFG1234567813",
			VehicleTokenID:     null.Int64From(vehicleTokenIDwithSDValidDD),
			SyntheticTokenID:   null.Int64From(444),
			WalletIndex:        null.Int64From(7),
			OnboardingStatus:   53, // OnboardingStatusMintSuccess
			DeviceDefinitionID: null.StringFrom("test-dd-2025"),
		}
		require.NoError(t, minted.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
		t.Cleanup(func() {
			_, _ = minted.Delete(s.ctx, s.pdb.DBS().Writer)
			_, _ = disconnected.Delete(s.ctx, s.pdb.DBS().Writer)
		})

		payloadJSON, err := json.Marshal(VinsVerifyParams{Vins: []service.VinWithTokenID{
			{Vin: "ABCDEFG1234567813", VehicleTokenID: vehicleTokenIDwithSDValidDD},
		}})
		assert.NilError(t, err)
		response, _ := app.Test(test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON)))
		body, _ := io.ReadAll(response.Body)
		assert.Equal(t, fiber.StatusOK, response.StatusCode, string(body))
		assert.Assert(t, strings.Contains(string(body), service.DetailsReadyToFinalize), string(body))

		record, err := dbmodels.FindOnboarding(s.ctx, s.pdb.DBS().Reader, "ABCDEFG1234567813")
		require.NoError(t, err)
		assert.Equal(t, 53, record.OnboardingStatus, "the minted record must not be re-armed for a second mint")
	})

	s.Run("Doesn't resume a mint that went to another wallet", func() {
		t := s.T()
		minted := dbmodels.Onboarding{
			Vin:                "ABCDEFG1234567812",
			VehicleTokenID:     null.Int64From(vehicleTokenIDwithSDOtherOwner),
			SyntheticTokenID:   null.Int64From(sdTokenIDOtherOwner),
			WalletIndex:        null.Int64From(7),
			OnboardingStatus:   53, // OnboardingStatusMintSuccess
			DeviceDefinitionID: null.StringFrom("test-dd-2025"),
		}
		require.NoError(t, minted.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
		t.Cleanup(func() { _, _ = minted.Delete(s.ctx, s.pdb.DBS().Writer) })

		payloadJSON, err := json.Marshal(VinsVerifyParams{Vins: []service.VinWithTokenID{{Vin: "ABCDEFG1234567812"}}})
		assert.NilError(t, err)
		response, _ := app.Test(test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON)))
		assert.Equal(t, fiber.StatusBadRequest, response.StatusCode)
	})
}

func (s *VehicleControllerTestSuite) TestFinalizeOnboarding() {
	t := s.T()
	mockDeps := createMockDependencies(t)

	credStore := repository.NewTempCredsStore(new(cipher.ROT13Cipher))

	// Create repositories struct
	vehicleRepo := repository.NewVehicleRepository(&s.pdb, new(cipher.ROT13Cipher), &mockDeps.logger)
	onboardingRepo := repository.NewOnboardingRepository(&s.pdb, &mockDeps.logger)
	repos := &repository.Repositories{
		Vehicle:    vehicleRepo,
		Credential: credStore,
		Onboarding: onboardingRepo,
	}

	// Create a mock service for testing
	mockService := service.NewVehicleOnboardService(
		&config.Settings{},
		&mockDeps.logger,
		mockDeps.identity,
		s.river,
		s.ws,
		nil, // transactions client
		repos,
	)

	controller := NewVehicleOnboardController(
		&mockDeps.logger,
		mockService,
	)

	app := fiber.New(fiber.Config{
		EnableSplittingOnParsers: true,
	})

	app.Use(func(c *fiber.Ctx) error {
		// Simulate JWT middleware setting the user in Locals
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": ownerAdd,
		})
		c.Locals("user", token)
		return c.Next()
	})

	app.Use(helpers.NewWalletMiddleware())
	app.Post("/vehicle/finalize", controller.FinalizeOnboarding)

	s.Run("Empty VIN list", func() {
		// given
		reqBody := `{"vins": []}`
		req := test.BuildRequest("POST", "/vehicle/finalize", reqBody)

		// then
		resp, err := app.Test(req)

		// verify
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	s.Run("Invalid VINs", func() {
		// given
		reqBody := `{"vins": ["INVALIDVIN123"]}`
		req := test.BuildRequest("POST", "/vehicle/finalize", reqBody)

		// then
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		// verify
		body, _ := io.ReadAll(resp.Body)
		expectedResp := `{"error":"Invalid VINs provided"}`
		assert.Equal(t, string(body), expectedResp)
	})

	finalizeReq := func() *http.Request {
		return test.BuildRequest("POST", "/vehicle/finalize", `{"vins": ["`+vin+`"]}`)
	}
	insertMinted := func(t *testing.T, vehicleToken int64, sdToken int64, status int) dbmodels.Onboarding {
		record := dbmodels.Onboarding{
			Vin:              vin,
			SyntheticTokenID: null.Int64From(sdToken),
			VehicleTokenID:   null.Int64From(vehicleToken),
			WalletIndex:      null.Int64From(1),
			OnboardingStatus: status,
		}
		require.NoError(t, record.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
		t.Cleanup(func() {
			_, _ = dbmodels.Onboardings(dbmodels.OnboardingWhere.Vin.EQ(vin)).DeleteAll(s.ctx, s.pdb.DBS().Writer)
			_, _ = dbmodels.DeviceCommandRequests().DeleteAll(s.ctx, s.pdb.DBS().Writer)
			_, _ = dbmodels.SyntheticDevices(dbmodels.SyntheticDeviceWhere.Vin.EQ(vin)).DeleteAll(s.ctx, s.pdb.DBS().Writer)
		})
		return record
	}
	user := common.HexToAddress(ownerAdd)

	s.Run("Valid VINs onboarded and ready for finalization", func() {
		t := s.T()
		insertMinted(t, vehicleTokenID, sdTokenIDFinalize, 53)
		storeTeslaLogin(t, repos.Credential, ownerAdd, vin)

		resp, err := app.Test(finalizeReq())
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode, string(body))
		assert.Equal(t, string(body), `{"vehicles":[{"vin":"1HGCM82633A123456","vehicleTokenId":789,"syntheticTokenId":456}]}`)

		device, err := dbmodels.SyntheticDevices(dbmodels.SyntheticDeviceWhere.VehicleTokenID.EQ(null.IntFrom(vehicleTokenID))).One(s.ctx, s.pdb.DBS().Reader)
		require.NoError(t, err)
		assert.Equal(t, sdTokenIDFinalize, device.TokenID.Int)
		assert.Equal(t, "pending", device.SubscriptionStatus.String)

		// The Tesla login was used up.
		retrievedCreds, _ := repos.Credential.Retrieve(s.ctx, user)
		require.Nil(t, retrievedCreds)
	})

	s.Run("Refuses to finalize before the mint finished", func() {
		t := s.T()
		insertMinted(t, vehicleTokenID, sdTokenIDFinalize, 51) // OnboardingStatusMintPending
		storeTeslaLogin(t, repos.Credential, ownerAdd, vin)

		resp, err := app.Test(finalizeReq())
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		_, err = repos.Credential.Retrieve(s.ctx, user)
		require.NoError(t, err, "a refused finalize must not use up the Tesla login")
	})

	s.Run("Refuses to attach the caller's Tesla login to another wallet's vehicle", func() {
		t := s.T()
		insertMinted(t, vehicleTokenIDwithSDOtherOwner, sdTokenIDOtherOwner, 53)
		storeTeslaLogin(t, repos.Credential, ownerAdd, vin)

		resp, err := app.Test(finalizeReq())
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		exists, err := dbmodels.SyntheticDevices(dbmodels.SyntheticDeviceWhere.Vin.EQ(vin)).Exists(s.ctx, s.pdb.DBS().Reader)
		require.NoError(t, err)
		assert.Assert(t, !exists)
	})

	s.Run("Refuses a VIN the caller's Tesla login didn't list", func() {
		t := s.T()
		insertMinted(t, vehicleTokenID, sdTokenIDFinalize, 53)
		storeTeslaLogin(t, repos.Credential, ownerAdd, "ABCDEFG1234567811")

		resp, err := app.Test(finalizeReq())
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	})

	s.Run("Keeps the Tesla login when saving fails, so finalize can be retried", func() {
		t := s.T()
		insertMinted(t, vehicleTokenID, sdTokenIDFinalize, 53)
		storeTeslaLogin(t, repos.Credential, ownerAdd, vin)
		// A connected row for the same vehicle makes the save fail.
		conflicting := dbmodels.SyntheticDevice{
			Address:            common.HexToAddress("0x00000000000000000000000000000000000000c1").Bytes(),
			Vin:                vin,
			VehicleTokenID:     null.IntFrom(vehicleTokenID),
			TokenID:            null.IntFrom(999),
			WalletChildNumber:  null.IntFrom(99),
			SubscriptionStatus: null.StringFrom("active"),
		}
		require.NoError(t, conflicting.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

		resp, err := app.Test(finalizeReq())
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

		_, err = repos.Credential.Retrieve(s.ctx, user)
		require.NoError(t, err, "a failed finalize must leave the Tesla login for the retry")
		record, err := dbmodels.FindOnboarding(s.ctx, s.pdb.DBS().Reader, vin)
		require.NoError(t, err, "a failed finalize must leave the onboarding record")
		assert.Equal(t, 53, record.OnboardingStatus)

		_, err = conflicting.Delete(s.ctx, s.pdb.DBS().Writer)
		require.NoError(t, err)
		resp, err = app.Test(finalizeReq())
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})

	s.Run("Reconnects in place, keeping subscription status and command history", func() {
		t := s.T()
		insertMinted(t, vehicleTokenID, sdTokenIDFinalize, 53)
		storeTeslaLogin(t, repos.Credential, ownerAdd, vin)
		disconnected := dbmodels.SyntheticDevice{
			Address:            common.HexToAddress("0x00000000000000000000000000000000000000d1").Bytes(),
			Vin:                vin,
			VehicleTokenID:     null.IntFrom(vehicleTokenID),
			SubscriptionStatus: null.StringFrom("active"),
		}
		require.NoError(t, disconnected.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
		command := dbmodels.DeviceCommandRequest{ID: "cmd-before-disconnect", VehicleTokenID: vehicleTokenID, Command: "doors/lock", Status: "completed"}
		require.NoError(t, command.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

		resp, err := app.Test(finalizeReq())
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode, string(body))

		devices, err := dbmodels.SyntheticDevices(dbmodels.SyntheticDeviceWhere.VehicleTokenID.EQ(null.IntFrom(vehicleTokenID))).All(s.ctx, s.pdb.DBS().Reader)
		require.NoError(t, err)
		require.Len(t, devices, 1)
		sdAddress, err := s.ws.GetAddress(s.ctx, 1)
		require.NoError(t, err)
		assert.DeepEqual(t, sdAddress.Bytes(), devices[0].Address)
		assert.Equal(t, sdTokenIDFinalize, devices[0].TokenID.Int)
		assert.Equal(t, "active", devices[0].SubscriptionStatus.String)
		assert.Assert(t, devices[0].AccessToken.Valid)

		exists, err := dbmodels.DeviceCommandRequestExists(s.ctx, s.pdb.DBS().Reader, command.ID)
		require.NoError(t, err)
		assert.Assert(t, exists, "command history must survive a reconnect")
	})
}

func (s *VehicleControllerTestSuite) TestMintEndpointsRequireTheTeslaLogin() {
	t := s.T()
	mockDeps := createMockDependencies(t)
	credStore := repository.NewTempCredsStore(new(cipher.ROT13Cipher))
	storeTeslaLogin(t, credStore, ownerAdd, "ABCDEFG1234567812")

	repos := &repository.Repositories{
		Vehicle:    repository.NewVehicleRepository(&s.pdb, new(cipher.ROT13Cipher), &mockDeps.logger),
		Credential: credStore,
		Onboarding: repository.NewOnboardingRepository(&s.pdb, &mockDeps.logger),
	}
	onboardSvc := service.NewVehicleOnboardService(&config.Settings{}, &mockDeps.logger, mockDeps.identity, s.river, s.ws, nil, repos)
	controller := NewVehicleOnboardController(&mockDeps.logger, onboardSvc)

	app := fiber.New(fiber.Config{EnableSplittingOnParsers: true})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user", jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"ethereum_address": ownerAdd}))
		return c.Next()
	})
	app.Use(helpers.NewWalletMiddleware())
	app.Get("/vehicle/mint", controller.GetMintDataForVins)
	app.Post("/vehicle/mint", controller.SubmitMintDataForVins)

	// A car someone else is onboarding: its record exists, the caller's Tesla can't see it.
	otherVin := dbmodels.Onboarding{
		Vin:                "ABCDEFG1234567899",
		OnboardingStatus:   23, // OnboardingStatusVendorValidationSuccess
		DeviceDefinitionID: null.StringFrom("test-dd-2025"),
	}
	require.NoError(t, otherVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

	s.Run("mint data refuses a VIN the Tesla login didn't list", func() {
		response, _ := app.Test(test.BuildRequest("GET", "/vehicle/mint?vins=ABCDEFG1234567899", ""))
		assert.Equal(s.T(), fiber.StatusForbidden, response.StatusCode)
	})

	s.Run("submit refuses a VIN the Tesla login didn't list", func() {
		payload, err := json.Marshal(MintDataForVins{VinMintingData: []service.VinTransactionData{{Vin: "ABCDEFG1234567899", Signature: []byte{1}}}})
		require.NoError(s.T(), err)
		response, _ := app.Test(test.BuildRequest("POST", "/vehicle/mint", string(payload)))
		assert.Equal(s.T(), fiber.StatusForbidden, response.StatusCode)
	})

	// Submitting a VIN with no record used to create one with no device definition.
	// Its mint then failed, and the half-made record blocked the VIN for everyone.
	s.Run("submit won't create a record for a VIN nobody verified", func() {
		t := s.T()
		payload, err := json.Marshal(MintDataForVins{VinMintingData: []service.VinTransactionData{{Vin: "ABCDEFG1234567812", Signature: []byte{1}}}})
		require.NoError(t, err)
		response, _ := app.Test(test.BuildRequest("POST", "/vehicle/mint", string(payload)))
		body, _ := io.ReadAll(response.Body)
		assert.Equal(t, fiber.StatusBadRequest, response.StatusCode, string(body))

		exists, err := dbmodels.OnboardingExists(s.ctx, s.pdb.DBS().Reader, "ABCDEFG1234567812")
		require.NoError(t, err)
		assert.Assert(t, !exists)
	})
}
