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

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/shared/pkg/redis"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/helpers"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/test"
	mods "github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/volatiletech/null/v8"
	"github.com/volatiletech/sqlboiler/v4/boil"

	rd "github.com/go-redis/redis/v8"
	"github.com/testcontainers/testcontainers-go/wait"
)

const vin = "1HGCM82633A123456"
const walletAddress = "0x1234567890AbcdEF1234567890aBcdef12345678"

type TeslaControllerTestSuite struct {
	suite.Suite
	pdb       db.Store
	container testcontainers.Container
	ctx       context.Context
	settings  config.Settings
}

const migrationsDirRelPath = "../../migrations"
const vehicleTokenID = 789

// SetupSuite starts container db
func (s *TeslaControllerTestSuite) SetupSuite() {
	s.ctx = context.Background()
	s.pdb, s.container, s.settings = test.StartContainerDatabase(context.Background(), s.T(), migrationsDirRelPath)

	fmt.Println("Suite setup completed.")
}

// TearDownTest after each test truncate tables
func (s *TeslaControllerTestSuite) TearDownTest() {
	fmt.Println("Truncating database ...")
	test.TruncateTables(s.pdb.DBS().Writer.DB, s.T())
}

// TearDownSuite cleanup at end by terminating container
func (s *TeslaControllerTestSuite) TearDownSuite() {
	fmt.Printf("shutting down postgres at with session: %s \n", s.container.SessionID())
	if err := s.container.Terminate(s.ctx); err != nil {
		s.T().Fatal(err)
	}

	fmt.Println("Suite teardown completed.")
}

func TestTeslaControllerTestSuite(t *testing.T) {
	suite.Run(t, new(TeslaControllerTestSuite))
}

func (s *TeslaControllerTestSuite) TestTelemetrySubscribe() {
	testCases := []struct {
		name                       string
		fleetStatus                *service.VehicleFleetStatus
		expectedAction             string
		expectedStatusCode         int
		expectedSubscriptionStatus string
	}{
		{
			name: "Start Streaming",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      true,
			},
			expectedAction:             mods.ActionSetTelemetryConfig,
			expectedStatusCode:         fiber.StatusOK,
			expectedSubscriptionStatus: "active",
		},
		{
			name: "Start Polling",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired: false,
				FirmwareVersion:                "2025.21.11",
			},
			expectedAction:             mods.ActionStartPolling,
			expectedStatusCode:         fiber.StatusOK,
			expectedSubscriptionStatus: "active",
		},
		{
			name: "Open Tesla Deeplink",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      false,
			},
			expectedAction:             mods.ActionOpenTeslaDeeplink,
			expectedStatusCode:         fiber.StatusConflict,
			expectedSubscriptionStatus: "pending",
		},
		{
			name: "Update Firmware",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired: false,
				FirmwareVersion:                "2023.10.5",
			},
			expectedAction:             mods.ActionUpdateFirmware,
			expectedStatusCode:         fiber.StatusConflict,
			expectedSubscriptionStatus: "pending",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// given
			wallet := common.HexToAddress(walletAddress)
			mockTeslaService := new(test.MockTeslaFleetAPIService)
			mockDevicesService := new(test.MockDevicesGRPCService)

			if tc.expectedAction == mods.ActionSetTelemetryConfig {
				mockTeslaService.On("SubscribeForTelemetryData", mock.Anything, mock.Anything, vin).Return(nil)
				mockTeslaService.On("GetTelemetrySubscriptionStatus", mock.Anything, mock.Anything, vin).Return(&service.VehicleTelemetryStatus{LimitReached: false}, nil)
			} else if tc.expectedAction == mods.ActionStartPolling {
				mockDevicesService.On("StartTeslaTask", mock.Anything, int64(vehicleTokenID)).Return(nil)
			}

			mockTeslaService.On("VirtualKeyConnectionStatus", mock.Anything, "mockAccessToken", vin).Return(tc.fleetStatus, nil)

			settings := config.Settings{MobileAppDevLicense: wallet, DevicesGRPCEndpoint: "localhost:50051"}
			logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
			teslaSvc := service.NewTeslaService(&settings, &logger, new(cipher.ROT13Cipher), &s.pdb)
			encryptedAccessToken, _ := teslaSvc.Cipher.Encrypt("mockAccessToken")
			encryptedRefreshToken, _ := teslaSvc.Cipher.Encrypt("mockRefreshToken")

			currentTime := time.Now()
			accessExpireAt := currentTime.Add(time.Hour)
			refreshExpireAt := currentTime.AddDate(0, 3, 0)
			dbVin := models.SyntheticDevice{
				Address:           common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12").Bytes(),
				Vin:               vin,
				TokenID:           null.NewInt(789, true),
				VehicleTokenID:    null.NewInt(vehicleTokenID, true),
				WalletChildNumber: 111,
				AccessToken:       null.StringFrom(encryptedAccessToken),
				RefreshToken:      null.StringFrom(encryptedRefreshToken),
				AccessExpiresAt:   null.TimeFrom(accessExpireAt.In(time.UTC)),
				RefreshExpiresAt:  null.TimeFrom(refreshExpireAt.In(time.UTC)),
			}

			require.NoError(s.T(), dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
			controller := NewTeslaController(&settings, &logger, mockTeslaService, nil, nil, nil, nil, *teslaSvc, &s.pdb)
			controller.devicesService = mockDevicesService

			app := fiber.New()
			app.Use(func(c *fiber.Ctx) error {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"ethereum_address": walletAddress,
				})
				c.Locals("user", token)
				return c.Next()
			})
			app.Use(helpers.NewWalletMiddleware())
			app.Post("/v1/tesla/telemetry/subscribe/:vehicleTokenId", controller.TelemetrySubscribe)

			req, _ := http.NewRequest(
				"POST",
				"/v1/tesla/telemetry/subscribe/789",
				nil,
			)
			req.Header.Set("Content-Type", "application/json")

			err := test.GenerateJWT(req)
			assert.NoError(s.T(), err)

			// when
			resp, err := app.Test(req)

			// then
			assert.NoError(s.T(), err)
			assert.Equal(s.T(), tc.expectedStatusCode, resp.StatusCode)

			if tc.expectedAction == mods.ActionSetTelemetryConfig {
				mockTeslaService.AssertCalled(s.T(), "SubscribeForTelemetryData", mock.Anything, mock.Anything, vin)
			} else if tc.expectedAction == mods.ActionStartPolling {
				mockDevicesService.AssertCalled(s.T(), "StartTeslaTask", mock.Anything, int64(vehicleTokenID))
			}

			// Query the database to verify subscription status
			device, err := models.SyntheticDevices(
				models.SyntheticDeviceWhere.VehicleTokenID.EQ(null.NewInt(vehicleTokenID, true))).One(s.ctx, s.pdb.DBS().Reader)
			require.NoError(s.T(), err)

			// Assert that the subscription status is set and not empty
			assert.True(s.T(), device.SubscriptionStatus.Valid)
			assert.Equal(s.T(), tc.expectedSubscriptionStatus, device.SubscriptionStatus.String)

			mockTeslaService.AssertExpectations(s.T())
			mockDevicesService.AssertExpectations(s.T())

			// I need at the end to clear db
			_, err = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
			if err != nil {
				s.T().Errorf("Failed to delete dbVin: %v", err)
			}
		})
	}
}

func (s *TeslaControllerTestSuite) TestStartDataFlow() {
	testCases := []struct {
		name                       string
		fleetStatus                *service.VehicleFleetStatus
		expectedAction             string
		expectedStatusCode         int
		expectedConfigLimitReached bool
	}{
		{
			name: "Start Streaming",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      true,
			},
			expectedAction:             mods.ActionSetTelemetryConfig,
			expectedStatusCode:         fiber.StatusOK,
			expectedConfigLimitReached: false,
		},
		{
			name: "Start Polling",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired: false,
				FirmwareVersion:                "2025.21.11",
			},
			expectedAction:             mods.ActionStartPolling,
			expectedStatusCode:         fiber.StatusOK,
			expectedConfigLimitReached: false,
		},
		{
			name: "Vehicle Not Ready",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      false,
			},
			expectedAction:             mods.ActionOpenTeslaDeeplink,
			expectedStatusCode:         fiber.StatusConflict,
			expectedConfigLimitReached: false,
		},
		{
			name: "Telemetry subscription limit reached",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      true,
			},
			expectedAction:             mods.ActionDummy,
			expectedStatusCode:         fiber.StatusConflict,
			expectedConfigLimitReached: true,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// given
			wallet := common.HexToAddress(walletAddress)
			synthDeviceAddressStr := "0xabcdef1234567890abcdef1234567890abcdef12"
			mockTeslaService := new(test.MockTeslaFleetAPIService)
			mockDevicesService := new(test.MockDevicesGRPCService)

			if tc.expectedAction == mods.ActionSetTelemetryConfig {
				mockTeslaService.On("SubscribeForTelemetryData", mock.Anything, mock.Anything, vin).Return(nil)
				mockTeslaService.On("GetTelemetrySubscriptionStatus", mock.Anything, mock.Anything, vin).Return(&service.VehicleTelemetryStatus{LimitReached: tc.expectedConfigLimitReached}, nil)
			} else if tc.expectedAction == mods.ActionStartPolling {
				mockDevicesService.On("StartTeslaTask", mock.Anything, int64(vehicleTokenID)).Return(nil)
			} else if tc.expectedAction == mods.ActionDummy {
				mockTeslaService.On("GetTelemetrySubscriptionStatus", mock.Anything, mock.Anything, vin).Return(&service.VehicleTelemetryStatus{LimitReached: tc.expectedConfigLimitReached}, nil)
			}

			mockTeslaService.On("VirtualKeyConnectionStatus", mock.Anything, "mockAccessToken", vin).Return(tc.fleetStatus, nil)

			settings := config.Settings{MobileAppDevLicense: wallet, DevicesGRPCEndpoint: "localhost:50051"}
			logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
			teslaSvc := service.NewTeslaService(&settings, &logger, new(cipher.ROT13Cipher), &s.pdb)
			encryptedAccessToken, _ := teslaSvc.Cipher.Encrypt("mockAccessToken")
			encryptedRefreshToken, _ := teslaSvc.Cipher.Encrypt("mockRefreshToken")

			currentTime := time.Now()
			accessExpireAt := currentTime.Add(time.Hour)
			refreshExpireAt := currentTime.AddDate(0, 3, 0)
			initialSubscriptionStatus := "pending"
			dbVin := models.SyntheticDevice{
				Address:            common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12").Bytes(),
				Vin:                vin,
				TokenID:            null.NewInt(789, true),
				VehicleTokenID:     null.NewInt(vehicleTokenID, true),
				WalletChildNumber:  111,
				AccessToken:        null.StringFrom(encryptedAccessToken),
				RefreshToken:       null.StringFrom(encryptedRefreshToken),
				AccessExpiresAt:    null.TimeFrom(accessExpireAt.In(time.UTC)),
				RefreshExpiresAt:   null.TimeFrom(refreshExpireAt.In(time.UTC)),
				SubscriptionStatus: null.StringFrom(initialSubscriptionStatus),
			}

			mockIdentitySvc := new(test.MockIdentityAPIService)
			mockVehicle := &mods.Vehicle{
				Owner:   walletAddress,
				TokenID: vehicleTokenID,
				SyntheticDevice: mods.SyntheticDevice{
					Address: synthDeviceAddressStr,
				},
			}
			mockIdentitySvc.On("FetchVehicleByTokenID", int64(vehicleTokenID)).Return(mockVehicle, nil)

			require.NoError(s.T(), dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
			controller := NewTeslaController(&settings, &logger, mockTeslaService, nil, mockIdentitySvc, nil, nil, *teslaSvc, &s.pdb)
			controller.devicesService = mockDevicesService

			app := fiber.New()
			app.Use(func(c *fiber.Ctx) error {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"ethereum_address": walletAddress,
				})
				c.Locals("user", token)
				return c.Next()
			})
			app.Use(helpers.NewWalletMiddleware())
			app.Post("/v1/tesla/start/:vehicleTokenId", controller.StartDataFlow)

			req, _ := http.NewRequest(
				"POST",
				"/v1/tesla/start/789",
				nil,
			)
			req.Header.Set("Content-Type", "application/json")

			err := test.GenerateJWT(req)
			assert.NoError(s.T(), err)

			// when
			resp, err := app.Test(req)

			// then
			assert.NoError(s.T(), err)
			assert.Equal(s.T(), tc.expectedStatusCode, resp.StatusCode)

			if tc.expectedAction == mods.ActionSetTelemetryConfig {
				mockTeslaService.AssertCalled(s.T(), "SubscribeForTelemetryData", mock.Anything, mock.Anything, vin)
			} else if tc.expectedAction == mods.ActionStartPolling {
				mockDevicesService.AssertCalled(s.T(), "StartTeslaTask", mock.Anything, int64(vehicleTokenID))
			}

			// Query the database to verify subscription status remains unchanged
			device, err := models.SyntheticDevices(
				models.SyntheticDeviceWhere.VehicleTokenID.EQ(null.NewInt(vehicleTokenID, true))).One(s.ctx, s.pdb.DBS().Reader)
			require.NoError(s.T(), err)

			// Assert that the subscription status remains unchanged
			assert.True(s.T(), device.SubscriptionStatus.Valid)
			assert.Equal(s.T(), initialSubscriptionStatus, device.SubscriptionStatus.String)

			mockTeslaService.AssertExpectations(s.T())
			mockDevicesService.AssertExpectations(s.T())
			mockIdentitySvc.AssertExpectations(s.T())

			// Clean up the database
			_, err = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
			if err != nil {
				s.T().Errorf("Failed to delete dbVin: %v", err)
			}
		})
	}
}

func (s *TeslaControllerTestSuite) TestTelemetryUnSubscribe() {
	// given
	synthDeviceAddressStr := "0xabcdef1234567890abcdef1234567890abcdef12"
	synthDeviceAddress := common.HexToAddress(synthDeviceAddressStr)
	wallet := common.HexToAddress(walletAddress)

	// Insert a synthetic device with the wallet address and VIN
	dbVin := models.SyntheticDevice{
		Address:           synthDeviceAddress.Bytes(),
		Vin:               vin,
		TokenID:           null.NewInt(456, true),
		VehicleTokenID:    null.NewInt(vehicleTokenID, true),
		WalletChildNumber: 111,
	}
	require.NoError(s.T(), dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

	// when
	mockIdentitySvc := new(test.MockIdentityAPIService)
	mockVehicle := &mods.Vehicle{
		Owner:   walletAddress,
		TokenID: vehicleTokenID,
		SyntheticDevice: mods.SyntheticDevice{
			Address: synthDeviceAddressStr,
		},
	}
	mockIdentitySvc.On("FetchVehicleByTokenID", int64(vehicleTokenID)).Return(mockVehicle, nil)
	mockCredStore := new(test.MockCredStore)
	mockTeslaService := new(test.MockTeslaFleetAPIService)

	mockTeslaService.On("GetPartnersToken", mock.Anything).Return(&service.PartnersAccessTokenResponse{
		AccessToken: "someToken",
		ExpiresIn:   22222,
		TokenType:   "Bearer",
	},
		nil,
	)
	mockTeslaService.On("UnSubscribeFromTelemetryData", mock.Anything, "someToken", vin).Return(nil)

	// Mock the DevicesGRPCService
	mockDevicesService := new(test.MockDevicesGRPCService)
	mockDevicesService.On("StopTeslaTask", mock.Anything, int64(vehicleTokenID)).Return(nil)

	// Initialize the controller
	settings := config.Settings{MobileAppDevLicense: wallet, DevicesGRPCEndpoint: "localhost:50051"}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	teslaSvc := service.NewTeslaService(&settings, &logger, new(cipher.ROT13Cipher), &s.pdb)
	controller := NewTeslaController(&settings, &logger, mockTeslaService, nil, mockIdentitySvc, mockCredStore, nil, *teslaSvc, &s.pdb)
	controller.devicesService = mockDevicesService

	// Set up the Fiber app
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		// Simulate JWT middleware setting the user in Locals
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": walletAddress,
		})
		c.Locals("user", token)
		return c.Next()
	})
	app.Use(helpers.NewWalletMiddleware())
	app.Delete("/v1/tesla/telemetry/unsubscribe/:vehicleTokenId", controller.UnsubscribeTelemetry)

	// Create a test HTTP request
	req, _ := http.NewRequest(
		"DELETE",
		"/v1/tesla/telemetry/unsubscribe/789",
		nil,
	)

	// Generate a valid JWT token
	err := test.GenerateJWT(req)
	assert.NoError(s.T(), err)

	// then
	resp, err := app.Test(req)

	// verify
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), fiber.StatusOK, resp.StatusCode)

	// Query the database to verify subscription status
	device, err := models.SyntheticDevices(
		models.SyntheticDeviceWhere.VehicleTokenID.EQ(null.NewInt(vehicleTokenID, true))).One(s.ctx, s.pdb.DBS().Reader)
	require.NoError(s.T(), err)

	// Assert that the subscription status is set and not empty
	assert.True(s.T(), device.SubscriptionStatus.Valid)
	assert.Equal(s.T(), "inactive", device.SubscriptionStatus.String)

	// Verify mock expectations
	mockCredStore.AssertExpectations(s.T())
	mockTeslaService.AssertExpectations(s.T())
	mockDevicesService.AssertExpectations(s.T())
}

func (s *TeslaControllerTestSuite) TestListVehicles() {
	// prepare
	onboardings := models.Onboarding{
		Vin:              vin,
		SyntheticTokenID: null.NewInt64(456, true),
		VehicleTokenID:   null.NewInt64(vehicleTokenID, true),
	}
	require.NoError(s.T(), onboardings.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

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

	// given
	credStore := service.TempCredsStore{
		Cache:  cacheService,
		Cipher: new(cipher.ROT13Cipher), // Example cipher
	}

	expectedVehicles := []TeslaVehicle{
		{
			VIN:        vin,
			ExternalID: "1",
			Definition: DeviceDefinition{Make: "", Model: "Model 3", Year: 2019, DeviceDefinitionID: "12345"},
		},
	}

	teslaVehicles := []service.TeslaVehicle{
		{
			VIN:       vin,
			ID:        1,
			VehicleID: vehicleTokenID,
		},
	}

	signedToken := generateTokenWithClaims()
	expectedResponse := &service.TeslaAuthCodeResponse{
		AccessToken:  signedToken,
		RefreshToken: "mockRefreshToken",
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
		Region:       "NA",
	}
	authCode := "testAuthCode"
	redirectURI := "https://example.com/callback"

	expectedDeviceDefinition := &mods.DeviceDefinition{
		DeviceDefinitionID: "12345",
		Model:              "Model 3",
		Year:               2019,
	}

	// when
	mockIdentitySvc := new(test.MockIdentityAPIService)
	mockTeslaService := new(test.MockTeslaFleetAPIService)
	mockDDService := new(test.MockDeviceDefinitionsAPIService)

	mockDDService.On("DecodeVin", "1HGCM82633A123456", "USA").Return(&service.DecodeVinResponse{
		DeviceDefinitionID: "12345",
		NewTransactionHash: "0xabc123",
	}, nil)
	mockTeslaService.On("CompleteTeslaAuthCodeExchange", mock.Anything, authCode, redirectURI).Return(expectedResponse, nil)
	mockTeslaService.On("GetVehicles", mock.Anything, signedToken).Return(teslaVehicles, nil)
	mockIdentitySvc.On("FetchDeviceDefinitionByID", "12345").Return(expectedDeviceDefinition, nil)

	// then
	settings := config.Settings{DevicesGRPCEndpoint: "localhost:50051"}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	ons := service.NewOnboardingService(&s.pdb, &logger)
	teslaSvc := service.NewTeslaService(&settings, &logger, new(cipher.ROT13Cipher), &s.pdb)
	controller := NewTeslaController(&settings, &logger, mockTeslaService, mockDDService, mockIdentitySvc, &credStore, ons, *teslaSvc, &s.pdb)

	// Set up the Fiber app
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		// Simulate JWT middleware setting the user in Locals
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": walletAddress,
			"iss":              "tesla-oracle",
			"sub":              "user123",
			"aud":              "tesla-api",
			"exp":              time.Now().Add(time.Hour).Unix(),
			"iat":              time.Now().Unix(),
			"scp":              []string{"read:vehicles", "write:telemetry"},
			"ou_code":          "OU12345",
		})
		c.Locals("user", token)
		return c.Next()
	})
	app.Use(helpers.NewWalletMiddleware())
	app.Post("/v1/tesla/vehicles", controller.ListVehicles)

	requestBody := `{
		"authorizationCode": "testAuthCode",
		"redirectUri": "https://example.com/callback"
	}`
	req, _ := http.NewRequest("POST", "/v1/tesla/vehicles", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")

	err = generateJWT(req)
	assert.NoError(s.T(), err)
	resp, err := app.Test(req)

	// verify
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), fiber.StatusOK, resp.StatusCode)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("failed to close response body: %v\n", err)
		}
	}()

	var responseWrapper CompleteOAuthExchangeResponseWrapper
	err = json.Unmarshal(bodyBytes, &responseWrapper)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), expectedVehicles, responseWrapper.Vehicles)

	// Check if the vehicle was cached
	cachedVehicles, err := cacheService.Get(s.ctx, "credentials:"+walletAddress).Result()
	assert.NoError(s.T(), err)
	assert.NotEmpty(s.T(), cachedVehicles)

	// Verify mock expectations
	mockIdentitySvc.AssertExpectations(s.T())
	mockTeslaService.AssertExpectations(s.T())
}

func (s *TeslaControllerTestSuite) TestGetVirtualKeyStatus() {
	// given
	walletAdd := common.HexToAddress(walletAddress)

	// Initialize mocks
	mockTeslaService, mockCredStore := s.initMocks()

	// Mock Retrieve to return a valid TeslaAuth object
	mockCredStore.On("Retrieve", mock.Anything, walletAdd).Return(&service.Credential{
		AccessToken: "mockAccessToken",
	}, nil)

	// Mock VirtualKeyConnectionStatus to return the expected response
	expectedResponse := &service.VehicleFleetStatus{
		KeyPaired:                      true,
		VehicleCommandProtocolRequired: true,
		NumberOfKeys:                   1,
	}
	mockTeslaService.On("VirtualKeyConnectionStatus", mock.Anything, "mockAccessToken", vin).Return(expectedResponse, nil)

	// Initialize the controller
	settings := config.Settings{DevicesGRPCEndpoint: "localhost:50051"}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	teslaSvc := service.NewTeslaService(&settings, &logger, new(cipher.ROT13Cipher), &s.pdb)
	controller := NewTeslaController(&settings, &logger, mockTeslaService, nil, nil, mockCredStore, nil, *teslaSvc, &s.pdb)

	// Set up the Fiber app
	app := s.setupFiberApp("/v1/tesla/virtual-key", "GET", controller.GetVirtualKeyStatus)

	// Create the request
	req, err := createRequest("GET", "/v1/tesla/virtual-key?vin="+vin, "")
	require.NoError(s.T(), err)

	// Generate JWT token
	err = generateJWT(req)
	require.NoError(s.T(), err)

	// when
	resp, err := app.Test(req)

	// then
	require.NoError(s.T(), err)
	assert.Equal(s.T(), fiber.StatusOK, resp.StatusCode)

	// Parse the response
	var response VirtualKeyStatusResponse
	err = parseResponse(resp, &response)
	require.NoError(s.T(), err)

	// Assert the response fields
	assert.True(s.T(), response.Added)
	assert.Equal(s.T(), VirtualKeyStatus(1), response.Status)

	// Verify mock expectations
	mockCredStore.AssertExpectations(s.T())
	mockTeslaService.AssertExpectations(s.T())
}

func (s *TeslaControllerTestSuite) TestGetStatus() {
	testCases := []struct {
		name               string
		fleetStatus        *service.VehicleFleetStatus
		expectedResponse   *mods.StatusDecision
		expectedStatusCode int
	}{
		{
			name: "VehicleCommandProtocolRequired and KeyPaired",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      true,
			},
			expectedResponse: &mods.StatusDecision{
				Message: mods.MessageReadyToStartDataFlow,
				Next: &mods.NextAction{
					Method:   "POST",
					Endpoint: "/v1/tesla/telemetry/subscribe/" + fmt.Sprint(vehicleTokenID),
				},
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name: "VehicleCommandProtocolRequired and KeyNotPaired",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      false,
			},
			expectedResponse: &mods.StatusDecision{
				Message: mods.MessageVirtualKeyNotPaired,
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name: "Firmware too old",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired: false,
				FirmwareVersion:                "2023.10.14",
			},
			expectedResponse: &mods.StatusDecision{
				Message: mods.MessageFirmwareTooOld,
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name: "Start Polling",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired: false,
				FirmwareVersion:                "2025.21.11",
			},
			expectedResponse: &mods.StatusDecision{
				Message: mods.MessageReadyToStartDataFlow,
				Next: &mods.NextAction{
					Method:   "POST",
					Endpoint: "/v1/tesla/telemetry/subscribe/" + fmt.Sprint(vehicleTokenID),
				},
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name: "Prompt to Toggle",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired:     false,
				SafetyScreenStreamingToggleEnabled: func(b bool) *bool { return &b }(false),
				FirmwareVersion:                    "2025.21.11",
			},
			expectedResponse: &mods.StatusDecision{
				Message: mods.MessageStreamingToggleDisabled,
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name: "SafetyScreenStreamingToggleEnabled",
			fleetStatus: &service.VehicleFleetStatus{
				VehicleCommandProtocolRequired:     false,
				SafetyScreenStreamingToggleEnabled: func(b bool) *bool { return &b }(true),
				FirmwareVersion:                    "2025.21.11",
			},
			expectedResponse: &mods.StatusDecision{
				Message: mods.MessageReadyToStartDataFlow,
				Next: &mods.NextAction{
					Method:   "POST",
					Endpoint: "/v1/tesla/telemetry/subscribe/" + fmt.Sprint(vehicleTokenID),
				},
			},
			expectedStatusCode: fiber.StatusOK,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// given
			synthDeviceAddressStr := "0xabcdef1234567890abcdef1234567890abcdef12"
			settings := config.Settings{DevicesGRPCEndpoint: "localhost:50051"}
			logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
			teslaSvc := service.NewTeslaService(&settings, &logger, new(cipher.ROT13Cipher), &s.pdb)
			encryptedAccessToken, _ := teslaSvc.Cipher.Encrypt("mockAccessToken")
			encryptedRefreshToken, _ := teslaSvc.Cipher.Encrypt("mockRefreshToken")
			synthDeviceAddress := common.HexToAddress(synthDeviceAddressStr)
			dbVin := models.SyntheticDevice{
				Address:           synthDeviceAddress.Bytes(),
				Vin:               vin,
				TokenID:           null.NewInt(456, true),
				VehicleTokenID:    null.NewInt(vehicleTokenID, true),
				WalletChildNumber: 111,
				AccessToken:       null.StringFrom(encryptedAccessToken),
				RefreshToken:      null.StringFrom(encryptedRefreshToken),
			}
			require.NoError(s.T(), dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

			// when
			mockIdentitySvc := new(test.MockIdentityAPIService)
			mockVehicle := &mods.Vehicle{
				Owner:   walletAddress,
				TokenID: vehicleTokenID,
				SyntheticDevice: mods.SyntheticDevice{
					Address: synthDeviceAddressStr,
				},
			}
			mockIdentitySvc.On("FetchVehicleByTokenID", int64(vehicleTokenID)).Return(mockVehicle, nil)

			mockTeslaService, mockCredStore := s.initMocks()
			mockTeslaService.On("VirtualKeyConnectionStatus", mock.Anything, "mockAccessToken", vin).Return(tc.fleetStatus, nil)

			// Setup Fiber app and request
			controller := NewTeslaController(&settings, &logger, mockTeslaService, nil, mockIdentitySvc, mockCredStore, nil, *teslaSvc, &s.pdb)
			app := fiber.New()
			app.Use(func(c *fiber.Ctx) error {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"ethereum_address": walletAddress,
				})
				c.Locals("user", token)
				return c.Next()
			})
			app.Use(helpers.NewWalletMiddleware())
			app.Get("/v1/tesla/:vehicleTokenId/status", controller.GetStatus)
			req, _ := createRequest("GET", fmt.Sprintf("/v1/tesla/%d/status", vehicleTokenID), "")
			req.Header.Set("Authorization", "Bearer mockToken")

			// then
			resp, err := app.Test(req, -1)
			s.Require().NoError(err)

			// verify
			var actualResponse mods.StatusDecision
			err = parseResponse(resp, &actualResponse)
			s.Require().NoError(err)

			// Assert the response and status code
			s.Equal(tc.expectedStatusCode, resp.StatusCode)
			s.Equal(tc.expectedResponse.Message, actualResponse.Message)
			s.Equal(tc.expectedResponse.Next, actualResponse.Next)

			mockTeslaService.AssertExpectations(s.T())
			mockIdentitySvc.AssertExpectations(s.T())

			// I need at the end to clear db
			_, err = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
			if err != nil {
				s.T().Errorf("Failed to delete dbVin: %v", err)
			}
		})
	}
}

func (s *TeslaControllerTestSuite) TestGetStatusNotOwner() {
	// given
	synthDeviceAddressStr := "0xabcdef1234567890abcdef1234567890abcdef12"

	mockIdentitySvc := new(test.MockIdentityAPIService)
	mockVehicle := &mods.Vehicle{
		Owner:   "0xabcdef1234567890abcdef1234567890abcdef12",
		TokenID: vehicleTokenID,
		SyntheticDevice: mods.SyntheticDevice{
			Address: synthDeviceAddressStr,
		},
	}
	mockIdentitySvc.On("FetchVehicleByTokenID", int64(vehicleTokenID)).Return(mockVehicle, nil)
	mockTeslaService, mockCredStore := s.initMocks()

	settings := config.Settings{DevicesGRPCEndpoint: "localhost:50051"}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	teslaSvc := service.NewTeslaService(&settings, &logger, new(cipher.ROT13Cipher), &s.pdb)
	controller := NewTeslaController(&settings, &logger, mockTeslaService, nil, mockIdentitySvc, mockCredStore, nil, *teslaSvc, &s.pdb)
	synthDeviceAddress := common.HexToAddress(synthDeviceAddressStr)
	dbVin := models.SyntheticDevice{
		Address:           synthDeviceAddress.Bytes(),
		Vin:               vin,
		TokenID:           null.NewInt(456, true),
		VehicleTokenID:    null.NewInt(vehicleTokenID, true),
		WalletChildNumber: 111,
	}

	require.NoError(s.T(), dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

	app := s.setupFiberApp("/v1/tesla/:vehicleTokenId/status", "GET", controller.GetStatus)

	// when
	req, _ := createRequest("GET", fmt.Sprintf("/v1/tesla/%d/status", vehicleTokenID), "")
	err := generateJWT(req)
	assert.NoError(s.T(), err)

	// then
	resp, err := app.Test(req)

	// verify
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), fiber.StatusUnauthorized, resp.StatusCode)
	mockTeslaService.AssertExpectations(s.T())
}

func (s *TeslaControllerTestSuite) TestGetOrRefreshAccessToken() {
	testCases := []struct {
		name              string
		syntheticDevice   *models.SyntheticDevice
		decryptError      error
		decryptedToken    string
		refreshTokenValid bool
		refreshTokenError error
		expectedToken     string
		expectedError     string
	}{
		{
			name: "Valid access token",
			syntheticDevice: &models.SyntheticDevice{
				AccessToken:      null.StringFrom("encryptedAccessToken"),
				RefreshExpiresAt: null.TimeFrom(time.Now().Add(1 * time.Hour)),
			},
			decryptedToken: "validAccessToken",
			expectedToken:  "validAccessToken",
		},
		//{
		//	name: "Expired access token with valid refresh token",
		//	syntheticDevice: &models.SyntheticDevice{
		//		AccessToken:      null.StringFrom("expiredEncryptedToken"),
		//		RefreshToken:     null.StringFrom("validRefreshToken"),
		//		RefreshExpiresAt: null.TimeFrom(time.Now().Add(1 * time.Hour)),
		//	},
		//	decryptError:      errors.New("token expired"),
		//	refreshTokenValid: true,
		//	decryptedToken:    "newAccessToken",
		//	expectedToken:     "newAccessToken",
		//},
		//{
		//	name: "Expired refresh token",
		//	syntheticDevice: &models.SyntheticDevice{
		//		AccessToken:      null.StringFrom("expiredEncryptedToken"),
		//		RefreshToken:     null.StringFrom("expiredRefreshToken"),
		//		RefreshExpiresAt: null.TimeFrom(time.Now().Add(-1 * time.Hour)),
		//	},
		//	decryptError:  errors.New("token expired"),
		//	expectedError: "unauthorized",
		//},
		//{
		//	name: "Decryption error",
		//	syntheticDevice: &models.SyntheticDevice{
		//		AccessToken: null.StringFrom("invalidEncryptedToken"),
		//	},
		//	decryptError:  errors.New("decryption failed"),
		//	expectedError: "decryption failed",
		//},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// Mock the Cipher.Decrypt method
			mockCipher := new(MockCipher)
			mockCipher.On("Decrypt", tc.syntheticDevice.AccessToken.String).Return(tc.decryptedToken, tc.decryptError)

			// Mock the RefreshAccessToken method if needed
			if tc.refreshTokenValid {
				mockTeslaService := new(test.MockTeslaFleetAPIService)
				mockTeslaService.On("RefreshAccessToken", mock.Anything, tc.syntheticDevice.RefreshToken.String).Return(tc.decryptedToken, tc.refreshTokenError)
			}

			// Create a TeslaController instance with the mocked Cipher
			controller := &TeslaController{
				teslaService: service.TeslaService{
					Cipher: mockCipher,
				},
			}

			// Call the function
			logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
			token, err := controller.getOrRefreshAccessToken(nil, tc.syntheticDevice, logger)

			// Assert the results
			if tc.expectedError != "" {
				s.Require().Error(err)
				s.Contains(err.Error(), tc.expectedError)
			} else {
				s.Require().NoError(err)
				s.Equal(tc.expectedToken, token)
			}

			// Assert mock expectations
			mockCipher.AssertExpectations(s.T())
		})
	}
}

// MockCipher is a mock implementation of a Cipher interface.
type MockCipher struct {
	mock.Mock
}

// Encrypt mocks the Encrypt method.
func (m *MockCipher) Encrypt(data string) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

// Decrypt mocks the Decrypt method.
func (m *MockCipher) Decrypt(data string) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

func generateTokenWithClaims() string {
	secretKey := []byte("your-secret-key")

	// Define the claims for the token
	claims := jwt.MapClaims{
		"ethereum_address": walletAddress,
		"iss":              "tesla-oracle",
		"sub":              "user123",
		"aud":              "tesla-api",
		"exp":              time.Now().Add(time.Hour).Unix(),
		"iat":              time.Now().Unix(),
		"scp":              []string{"read:vehicles", "write:telemetry"},
		"ou_code":          "OU12345",
	}

	// Create a new token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		fmt.Println("Error signing token:", err)
		return ""
	}
	return signedToken
}

func generateJWT(req *http.Request) error {
	// Define the secret key for signing the token
	secretKey := []byte("your-secret-key")

	// Create claims with the required `ethereum_address`
	claims := jwt.MapClaims{
		"ethereum_address": walletAddress,                    // Valid Ethereum address
		"exp":              time.Now().Add(time.Hour).Unix(), // Token expiration time
	}

	// Create a new token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		fmt.Println("Error signing token:", err)
		return err
	}

	req.Header.Set("Authorization", "Bearer "+signedToken)
	return nil
}

func (s *TeslaControllerTestSuite) setupFiberApp(route string, method string, handler fiber.Handler) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": walletAddress,
		})
		c.Locals("user", token)
		return c.Next()
	})
	app.Use(helpers.NewWalletMiddleware())

	switch method {
	case "GET":
		app.Get(route, handler)
	case "POST":
		app.Post(route, handler)
	case "DELETE":
		app.Delete(route, handler)
	}
	return app
}

func createRequest(method, url, body string) (*http.Request, error) {
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, url, strings.NewReader(body))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	req.Header.Set("Content-Type", "application/json")
	return req, err
}

func parseResponse(resp *http.Response, target interface{}) error {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("failed to close response body: %v\n", err)
		}
	}()
	return json.Unmarshal(bodyBytes, target)
}
func (s *TeslaControllerTestSuite) initMocks() (*test.MockTeslaFleetAPIService, *test.MockCredStore) {
	mockTeslaService := new(test.MockTeslaFleetAPIService)
	mockCredStore := new(test.MockCredStore)
	return mockTeslaService, mockCredStore
}
