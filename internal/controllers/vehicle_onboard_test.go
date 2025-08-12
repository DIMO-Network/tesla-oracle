package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/shared/pkg/redis"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/helpers"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/test"
	mods "github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/onboarding"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	dbmodels "github.com/DIMO-Network/tesla-oracle/models"
	"github.com/ethereum/go-ethereum/common"
	rd "github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/boil"
	"gotest.tools/v3/assert"
)

const ownerAdd = "0x1234567890AbcdEF1234567890aBcdef12345678"
const owner2Add = "0x1234567890AbcdEF1234567890aBcdef12345679"
const sdWalletsSeed = "cabaabd8c7c7d27347349e48fb11319bc6656cb6cc1bdc717e94dae8db7e6bc2"

type VehicleControllerTestSuite struct {
	suite.Suite
	pdb           db.Store
	container     testcontainers.Container
	ctx           context.Context
	river         *river.Client[pgx.Tx]
	settings      config.Settings
	onboardingSvc *service.OnboardingService
	ws            *service.SDWalletsService
	logger        zerolog.Logger
}

// SetupSuite starts container db
func (s *VehicleControllerTestSuite) SetupSuite() {
	s.ctx = context.Background()
	s.logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	s.pdb, s.container, s.settings = test.StartContainerDatabase(context.Background(), s.T(), migrationsDirRelPath)
	s.ws = service.NewSDWalletsService(s.ctx, s.logger, config.Settings{SDWalletsSeed: sdWalletsSeed})
	s.onboardingSvc = service.NewOnboardingService(&s.pdb, &s.logger)

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
	credsStore CredStore
}

const vehicleTokenIDnoSDValidDD = 100
const vehicleTokenIDnoSDValidDDDifferentOwner = 110
const vehicleTokenIDwithSDValidDD = 120

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

	credsStore := new(test.MockCredStore)

	return deps{
		logger:     logger,
		identity:   identity,
		credsStore: credsStore,
	}
}

func (s *VehicleControllerTestSuite) TestVerifyVins() {
	t := s.T()
	mockDeps := createMockDependencies(t)

	c := NewVehicleOnboardController(
		&config.Settings{Port: 3000},
		&mockDeps.logger,
		mockDeps.identity,
		s.onboardingSvc,
		s.river,
		nil,
		nil,
		&s.pdb,
		mockDeps.credsStore,
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
			Vins: []VinWithTokenID{},
		})
		assert.NilError(t, err)

		req := test.BuildRequest("POST", "/vehicle/verify", string(payloadJSON))
		assert.NilError(s.T(), test.GenerateJWT(req))

		response, _ := app.Test(req)
		assert.Equal(t, fiber.StatusOK, response.StatusCode)

		body, _ := io.ReadAll(response.Body)
		expected := StatusForVinsResponse{
			Statuses: []VinStatus{},
		}

		expectedJSON, err := json.Marshal(expected)
		assert.NilError(t, err)

		assert.Equal(t, string(body), string(expectedJSON))
	})

	s.Run("Get verification status for a list of valid, but unknown VINs", func() {
		payloadJSON, err := json.Marshal(VinsVerifyParams{
			Vins: []VinWithTokenID{
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
			Vins: []VinWithTokenID{
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
		OnboardingStatus:   onboarding.OnboardingStatusVendorValidationSuccess,
		DeviceDefinitionID: null.StringFrom("test-dd-2025"),
	}

	s.Run("Get verification status for a list of valid VINs, some known, some not", func() {
		require.NoError(t, dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

		payloadJSON, err := json.Marshal(VinsVerifyParams{
			Vins: []VinWithTokenID{
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
			Vins: []VinWithTokenID{
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
			Vins: []VinWithTokenID{
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
			Statuses: []VinStatus{
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
			Vins: []VinWithTokenID{
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
			Statuses: []VinStatus{
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
			Vins: []VinWithTokenID{
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
			Statuses: []VinStatus{
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
			Vins: []VinWithTokenID{
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
			Statuses: []VinStatus{
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
			Vins: []VinWithTokenID{
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
			Statuses: []VinStatus{
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

}

func (s *VehicleControllerTestSuite) TestFinalizeOnboarding() {
	t := s.T()
	mockDeps := createMockDependencies(t)

	// Spin up a local Redis container
	redisContainer, err := testcontainers.GenericContainer(s.ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis:latest",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForListeningPort("6379/tcp"),
		},
		Started: true,
	})
	require.NoError(s.T(), err)
	defer func() {
		if err := redisContainer.Terminate(s.ctx); err != nil {
			s.T().Logf("failed to terminate Redis container: %v", err)
		}
	}()

	// Get the Redis container's host and port
	redisHost, err := redisContainer.Host(s.ctx)
	require.NoError(s.T(), err)
	redisPort, err := redisContainer.MappedPort(s.ctx, "6379")
	require.NoError(s.T(), err)

	// Connect to Redis
	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort.Port())
	redisClient := rd.NewClient(&rd.Options{
		Addr: redisAddr,
	})
	defer func() {
		if err := redisClient.Close(); err != nil {
			fmt.Printf("failed to close Redis client: %v\n", err)
		}
	}()

	// Create cacheService
	cacheService := redis.NewRedisCacheService(false, redis.Settings{
		URL:       redisAddr,
		Password:  "",
		TLS:       false,
		KeyPrefix: "tesla-oracle",
	})

	credStore := service.TempCredsStore{
		Cache:  cacheService,
		Cipher: new(cipher.ROT13Cipher), // Example cipher
	}

	controller := NewVehicleOnboardController(
		&s.settings,
		&mockDeps.logger,
		mockDeps.identity,
		s.onboardingSvc,
		s.river,
		s.ws,
		nil,
		&s.pdb,
		&credStore,
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

	s.Run("Valid VINs onboarded and ready for finalization", func() {
		// given
		// Insert a synthetic device with the wallet address and VIN
		onboardings := dbmodels.Onboarding{
			Vin:              vin,
			SyntheticTokenID: null.NewInt64(456, true),
			VehicleTokenID:   null.NewInt64(vehicleTokenID, true),
			WalletIndex:      null.NewInt64(1, true),
		}
		require.NoError(s.T(), onboardings.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

		// insert to cache
		user := common.HexToAddress(ownerAdd)
		creds := &service.Credential{
			AccessToken:   "access_token",
			RefreshToken:  "refresh_token",
			AccessExpiry:  time.Now().Add(1 * time.Hour),
			RefreshExpiry: time.Now().Add(24 * time.Hour),
		}
		if err := controller.credentials.Store(s.ctx, user, creds); err != nil {
			s.T().Fatalf("failed to store credentials: %v", err)
		}

		reqBody := `{"vins": ["1HGCM82633A123456"]}`
		req := test.BuildRequest("POST", "/vehicle/finalize", reqBody)

		// then
		resp, err := app.Test(req)

		// verify
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		expectedBody := `{"vehicles":[{"vin":"1HGCM82633A123456","vehicleTokenId":789,"syntheticTokenId":456}]}`
		assert.Equal(t, string(body), expectedBody)

		// Verify that the cache no longer contains the credentials
		retrievedCreds, _ := controller.credentials.Retrieve(s.ctx, user)
		require.Nil(t, retrievedCreds)
	})
}
