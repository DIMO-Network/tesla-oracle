package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/shared/pkg/db"
	"github.com/DIMO-Network/shared/pkg/redis"
	"github.com/DIMO-Network/tesla-oracle/internal/commands"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/helpers"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/test"
	"github.com/DIMO-Network/tesla-oracle/internal/core"
	mods "github.com/DIMO-Network/tesla-oracle/internal/models"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	"github.com/DIMO-Network/tesla-oracle/models"
	"github.com/aarondl/null/v8"
	"github.com/aarondl/sqlboiler/v4/boil"
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
		fleetStatus                *core.VehicleFleetStatus
		expectedAction             string
		expectedStatusCode         int
		expectedSubscriptionStatus string
	}{
		{
			name: "Start Streaming",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      true,
			},
			expectedAction:             service.ActionSetTelemetryConfig,
			expectedStatusCode:         fiber.StatusOK,
			expectedSubscriptionStatus: "active",
		},
		{
			name: "Start Polling",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired: false,
				FirmwareVersion:                "2025.21.11",
			},
			expectedAction:             service.ActionStartPolling,
			expectedStatusCode:         fiber.StatusOK,
			expectedSubscriptionStatus: "active",
		},
		{
			name: "Open Tesla Deeplink",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      false,
			},
			expectedAction:             service.ActionOpenTeslaDeeplink,
			expectedStatusCode:         fiber.StatusConflict,
			expectedSubscriptionStatus: "pending",
		},
		{
			name: "Update Firmware",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired: false,
				FirmwareVersion:                "2023.10.5",
			},
			expectedAction:             service.ActionUpdateFirmware,
			expectedStatusCode:         fiber.StatusConflict,
			expectedSubscriptionStatus: "pending",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// given
			settings, logger, repos := s.createTestDependencies()

			// when
			mockTeslaService, mockDevicesService := s.setupMockServices(tc.fleetStatus, tc.expectedAction, false)
			tokenManager := core.NewTeslaTokenManager(new(cipher.ROT13Cipher), repos.Vehicle, mockTeslaService, logger)
			teslaSvc := service.NewTeslaService(settings, logger, repos, mockTeslaService, nil, nil, mockDevicesService, *tokenManager)
			dbVin := s.createTestSyntheticDeviceWithStatus(new(cipher.ROT13Cipher), "")
			defer func() {
				_, _ = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
			}()

			controller := NewTeslaController(settings, logger, teslaSvc, nil, nil)
			app := s.setupTestApp("/v1/tesla/telemetry/subscribe/:vehicleTokenId", "POST", controller.TelemetrySubscribe)

			//  then
			req, _ := http.NewRequest("POST", "/v1/tesla/telemetry/subscribe/789", nil)
			req.Header.Set("Content-Type", "application/json")
			assert.NoError(s.T(), test.GenerateJWT(req))

			// Execute test
			resp, err := app.Test(req)

			// verify
			assert.NoError(s.T(), err)
			assert.Equal(s.T(), tc.expectedStatusCode, resp.StatusCode)
			s.assertMockCalls(mockTeslaService, mockDevicesService, tc.expectedAction)
			s.assertSubscriptionStatus(tc.expectedSubscriptionStatus, vehicleTokenID)
		})
	}
}

func (s *TeslaControllerTestSuite) TestStartDataFlow() {
	testCases := []struct {
		name                       string
		fleetStatus                *core.VehicleFleetStatus
		expectedAction             string
		expectedStatusCode         int
		expectedConfigLimitReached bool
	}{
		{
			name: "Start Streaming",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      true,
			},
			expectedAction:             service.ActionSetTelemetryConfig,
			expectedStatusCode:         fiber.StatusOK,
			expectedConfigLimitReached: false,
		},
		{
			name: "Start Polling",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired: false,
				FirmwareVersion:                "2025.21.11",
			},
			expectedAction:             service.ActionStartPolling,
			expectedStatusCode:         fiber.StatusOK,
			expectedConfigLimitReached: false,
		},
		{
			name: "Vehicle Not Ready",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      false,
			},
			expectedAction:             service.ActionOpenTeslaDeeplink,
			expectedStatusCode:         fiber.StatusConflict,
			expectedConfigLimitReached: false,
		},
		{
			name: "Telemetry subscription limit reached",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      true,
			},
			expectedAction:             service.ActionDummy,
			expectedStatusCode:         fiber.StatusConflict,
			expectedConfigLimitReached: true,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// given
			settings, logger, repos := s.createTestDependencies()

			// when
			mockTeslaService, mockDevicesService := s.setupMockServices(tc.fleetStatus, tc.expectedAction, tc.expectedConfigLimitReached)
			mockIdentitySvc := s.setupMockIdentityService()

			tokenManager := core.NewTeslaTokenManager(new(cipher.ROT13Cipher), repos.Vehicle, mockTeslaService, logger)
			teslaSvc := service.NewTeslaService(settings, logger, repos, mockTeslaService, mockIdentitySvc, nil, mockDevicesService, *tokenManager)
			dbVin := s.createTestSyntheticDeviceWithStatus(new(cipher.ROT13Cipher), "pending")
			defer func() {
				_, _ = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
			}()

			controller := NewTeslaController(settings, logger, teslaSvc, nil, nil)
			app := s.setupTestApp("/v1/tesla/telemetry/:vehicleTokenId/start", "POST", controller.StartDataFlow)

			// then
			req, _ := http.NewRequest("POST", "/v1/tesla/telemetry/789/start", nil)
			req.Header.Set("Content-Type", "application/json")
			assert.NoError(s.T(), test.GenerateJWT(req))

			resp, err := app.Test(req)

			// verify
			assert.NoError(s.T(), err)
			assert.Equal(s.T(), tc.expectedStatusCode, resp.StatusCode)
			s.assertMockCalls(mockTeslaService, mockDevicesService, tc.expectedAction)
			s.assertSubscriptionStatus("pending", vehicleTokenID) // Status should remain unchanged
			mockIdentitySvc.AssertExpectations(s.T())
		})
	}
}

func (s *TeslaControllerTestSuite) TestTelemetryUnSubscribe() {
	// given
	settings, logger, repos := s.createTestDependencies()

	// when
	mockTeslaService, mockDevicesService, mockIdentitySvc := s.setupUnsubscribeMocks()

	mockCredStore := repos.Credential.(*test.MockCredStore)
	tokenManager := core.NewTeslaTokenManager(new(cipher.ROT13Cipher), repos.Vehicle, mockTeslaService, logger)
	teslaSvc := service.NewTeslaService(settings, logger, repos, mockTeslaService, mockIdentitySvc, nil, mockDevicesService, *tokenManager)
	controller := NewTeslaController(settings, logger, teslaSvc, nil, nil)

	dbVin := s.createTestSyntheticDeviceWithStatus(new(cipher.ROT13Cipher), "active")
	defer func() {
		_, _ = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
	}()

	// then
	app := s.setupTestApp("/v1/tesla/telemetry/unsubscribe/:vehicleTokenId", "POST", controller.UnsubscribeTelemetry)
	req, _ := http.NewRequest("POST", "/v1/tesla/telemetry/unsubscribe/789", nil)
	assert.NoError(s.T(), test.GenerateJWT(req))

	resp, err := app.Test(req)

	//  verify
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), fiber.StatusOK, resp.StatusCode)
	s.assertSubscriptionStatus("inactive", vehicleTokenID)

	mockCredStore.AssertExpectations(s.T())
	mockTeslaService.AssertExpectations(s.T())
	mockDevicesService.AssertExpectations(s.T())
}

func (s *TeslaControllerTestSuite) TestListVehicles() {
	// given
	wallet := common.HexToAddress(walletAddress)
	settings := &config.Settings{MobileAppDevLicense: wallet, DevicesGRPCEndpoint: "localhost:50051"}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	vehicleRepo := repository.NewVehicleRepository(&s.pdb, new(cipher.ROT13Cipher), &logger)
	onboardingRepo := repository.NewOnboardingRepository(&s.pdb, &logger)

	onboardings := models.Onboarding{
		Vin:              vin,
		SyntheticTokenID: null.NewInt64(456, true),
		VehicleTokenID:   null.NewInt64(vehicleTokenID, true),
	}
	require.NoError(s.T(), onboardings.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
	defer func() {
		_, _ = onboardings.Delete(s.ctx, s.pdb.DBS().Writer)
	}()

	redisContainer, credStore, err := s.setupRedisContainer()
	require.NoError(s.T(), err)
	defer func() {
		if err := redisContainer.Terminate(s.ctx); err != nil {
			s.T().Logf("failed to terminate Redis container: %v", err)
		}
	}()

	// when
	mockIdentitySvc, mockTeslaService, mockDDService := s.setupListVehiclesMocks()
	repos := &repository.Repositories{
		Vehicle:    vehicleRepo,
		Credential: credStore,
		Onboarding: onboardingRepo,
	}
	tokenManager := core.NewTeslaTokenManager(new(cipher.ROT13Cipher), repos.Vehicle, mockTeslaService, &logger)
	teslaSvc := service.NewTeslaService(settings, &logger, repos, mockTeslaService, mockIdentitySvc, mockDDService, nil, *tokenManager)
	controller := NewTeslaController(settings, &logger, teslaSvc, nil, nil)
	app := s.setupTestAppForListVehicles(controller)

	// then
	requestBody := `{"authorizationCode": "testAuthCode", "redirectUri": "https://example.com/callback"}`
	req, _ := http.NewRequest("POST", "/v1/tesla/vehicles", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	assert.NoError(s.T(), test.GenerateJWT(req))

	resp, err := app.Test(req)

	// verify
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), fiber.StatusOK, resp.StatusCode)
	s.assertListVehiclesResponse(resp)

	mockIdentitySvc.AssertExpectations(s.T())
	mockTeslaService.AssertExpectations(s.T())
	mockDDService.AssertExpectations(s.T())
}

func (s *TeslaControllerTestSuite) TestGetVirtualKeyStatus() {
	// given
	settings, logger, repos := s.createTestDependencies()

	// when
	mockTeslaService, mockCredStore := s.setupVirtualKeyStatusMocks()
	repos.Credential = mockCredStore

	tokenManager := core.NewTeslaTokenManager(new(cipher.ROT13Cipher), repos.Vehicle, mockTeslaService, logger)
	teslaSvc := service.NewTeslaService(settings, logger, repos, mockTeslaService, nil, nil, nil, *tokenManager)
	controller := NewTeslaController(settings, logger, teslaSvc, nil, nil)

	// then
	app := s.setupFiberApp("/v1/tesla/virtual-key", "GET", controller.GetVirtualKeyStatus)
	req, _ := createRequest("GET", "/v1/tesla/virtual-key?vin="+vin, "")
	assert.NoError(s.T(), test.GenerateJWT(req))

	resp, err := app.Test(req)

	// verify
	require.NoError(s.T(), err)
	assert.Equal(s.T(), fiber.StatusOK, resp.StatusCode)
	s.assertVirtualKeyStatusResponse(resp)

	mockCredStore.AssertExpectations(s.T())
	mockTeslaService.AssertExpectations(s.T())
}

func (s *TeslaControllerTestSuite) TestGetStatus() {
	expectedStartEndpoint := fmt.Sprintf("/v1/tesla/telemetry/%d/start", vehicleTokenID)
	testCases := []struct {
		name               string
		fleetStatus        *core.VehicleFleetStatus
		expectedResponse   *mods.StatusDecision
		expectedStatusCode int
		telemetryStatus    bool
	}{
		{
			name: "VehicleCommandProtocolRequired and KeyPaired",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      true,
			},
			telemetryStatus: false,
			expectedResponse: &mods.StatusDecision{
				Message: service.MessageReadyToStartDataFlow,
				Next: &mods.NextAction{
					Method:   "POST",
					Endpoint: expectedStartEndpoint,
				},
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name: "VehicleCommandProtocolRequired and KeyNotPaired",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired: true,
				KeyPaired:                      false,
			},
			telemetryStatus: false,
			expectedResponse: &mods.StatusDecision{
				Message: service.MessageVirtualKeyNotPaired,
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name: "Firmware too old",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired: false,
				FirmwareVersion:                "2023.10.14",
			},
			telemetryStatus: false,
			expectedResponse: &mods.StatusDecision{
				Message: service.MessageFirmwareTooOld,
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name: "Start Polling",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired: false,
				FirmwareVersion:                "2025.21.11",
			},
			telemetryStatus: false,
			expectedResponse: &mods.StatusDecision{
				Message: service.MessageTelemetryConfigured,
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name: "Prompt to Toggle",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired:     false,
				SafetyScreenStreamingToggleEnabled: func(b bool) *bool { return &b }(false),
				FirmwareVersion:                    "2025.21.11",
			},
			telemetryStatus: false,
			expectedResponse: &mods.StatusDecision{
				Message: service.MessageStreamingToggleDisabled,
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name: "SafetyScreenStreamingToggleEnabled",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired:     false,
				SafetyScreenStreamingToggleEnabled: func(b bool) *bool { return &b }(true),
				FirmwareVersion:                    "2025.21.11",
			},
			telemetryStatus: false,
			expectedResponse: &mods.StatusDecision{
				Message: service.MessageReadyToStartDataFlow,
				Next: &mods.NextAction{
					Method:   "POST",
					Endpoint: expectedStartEndpoint,
				},
			},
			expectedStatusCode: fiber.StatusOK,
		},
		{
			name: "Telemetry already configured",
			fleetStatus: &core.VehicleFleetStatus{
				VehicleCommandProtocolRequired:     false,
				SafetyScreenStreamingToggleEnabled: func(b bool) *bool { return &b }(true),
				FirmwareVersion:                    "2025.21.11",
			},
			telemetryStatus: true,
			expectedResponse: &mods.StatusDecision{
				Message: service.MessageTelemetryConfigured,
			},
			expectedStatusCode: fiber.StatusOK,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// given
			settings, logger, repos := s.createTestDependencies()

			// when
			mockTeslaService, mockCredStore := s.setupGetStatusMocks(tc.fleetStatus)
			mockIdentitySvc := s.setupMockIdentityService()
			repos.Credential = mockCredStore

			// Add telemetry status mock for test cases that result in ActionSetTelemetryConfig
			if (tc.fleetStatus.VehicleCommandProtocolRequired && tc.fleetStatus.KeyPaired) ||
				(tc.fleetStatus.SafetyScreenStreamingToggleEnabled != nil && *tc.fleetStatus.SafetyScreenStreamingToggleEnabled) {
				mockTeslaService.On("GetTelemetrySubscriptionStatus", mock.Anything, mock.Anything, vin).Return(&core.VehicleTelemetryStatus{
					Configured: tc.telemetryStatus,
				}, nil)
			}

			tokenManager := core.NewTeslaTokenManager(new(cipher.ROT13Cipher), repos.Vehicle, mockTeslaService, logger)
			teslaSvc := service.NewTeslaService(settings, logger, repos, mockTeslaService, mockIdentitySvc, nil, nil, *tokenManager)
			dbVin := s.createTestSyntheticDeviceWithStatus(new(cipher.ROT13Cipher), "")
			defer func() {
				_, _ = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
			}()

			controller := NewTeslaController(settings, logger, teslaSvc, nil, nil)
			app := s.setupTestApp("/v1/tesla/:vehicleTokenId/status", "GET", controller.GetStatus)

			// then
			req, _ := createRequest("GET", fmt.Sprintf("/v1/tesla/%d/status", vehicleTokenID), "")
			req.Header.Set("Authorization", "Bearer mockToken")

			resp, err := app.Test(req, -1)
			s.Require().NoError(err)
			s.assertGetStatusResponse(resp, tc.expectedResponse, tc.expectedStatusCode)

			mockTeslaService.AssertExpectations(s.T())
			mockIdentitySvc.AssertExpectations(s.T())
		})
	}
}

func (s *TeslaControllerTestSuite) TestGetStatusNotOwner() {
	// given
	synthDeviceAddressStr := "0xabcdef1234567890abcdef1234567890abcdef12"

	// when
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
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})

	vehicleRepo := repository.NewVehicleRepository(&s.pdb, new(cipher.ROT13Cipher), &logger)
	onboardingRepo := repository.NewOnboardingRepository(&s.pdb, &logger)
	repos := &repository.Repositories{
		Vehicle:    vehicleRepo,
		Credential: mockCredStore,
		Onboarding: onboardingRepo,
	}

	settings := config.Settings{DevicesGRPCEndpoint: "localhost:50051"}
	tokenManager := core.NewTeslaTokenManager(new(cipher.ROT13Cipher), repos.Vehicle, mockTeslaService, &logger)
	teslaSvc := service.NewTeslaService(&settings, &logger, repos, mockTeslaService, mockIdentitySvc, nil, nil, *tokenManager)

	controller := func() *TeslaController {
		return NewTeslaController(&settings, &logger, teslaSvc, nil, nil)
	}()
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

	// then
	req, _ := createRequest("GET", fmt.Sprintf("/v1/tesla/%d/status", vehicleTokenID), "")
	err := generateJWT(req)
	assert.NoError(s.T(), err)

	resp, err := app.Test(req)

	// verify
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), fiber.StatusUnauthorized, resp.StatusCode)
	mockTeslaService.AssertExpectations(s.T())
}

// TODO: Fix this test after TeslaTokenManager migration - currently commented out
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
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// when
			mockCipher := new(test.MockCipher)
			mockCipher.On("Decrypt", tc.syntheticDevice.AccessToken.String).Return(tc.decryptedToken, tc.decryptError)

			mockTeslaService := new(test.MockTeslaFleetAPIService)
			if tc.refreshTokenValid {
				//mockTeslaService := new(test.MockTeslaFleetAPIService)
				mockTeslaService.On("RefreshAccessToken", mock.Anything, tc.syntheticDevice.RefreshToken.String).Return(tc.decryptedToken, tc.refreshTokenError)
			}
			logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
			tokenManager := core.NewTeslaTokenManager(mockCipher, nil, mockTeslaService, &logger)

			// then
			token, err := tokenManager.GetOrRefreshAccessToken(context.TODO(), tc.syntheticDevice)

			// verify
			if tc.expectedError != "" {
				s.Require().Error(err)
				s.Contains(err.Error(), tc.expectedError)
			} else {
				s.Require().NoError(err)
				s.Equal(tc.expectedToken, token)
			}

			mockCipher.AssertExpectations(s.T())
		})
	}
}

// TODO: Fix this test after River migration - currently commented out due to commandPublisher removal
/*func (s *TeslaControllerTestSuite) TestSubmitCommand() {
	testCases := []struct {
		name                  string
		command               string
		subscriptionStatus    string
		expectedStatusCode    int
		expectedCommandID     string
		expectedStatus        string
		expectedMessage       string
		publishCommandError   error
		saveCommandError      error
		vehicleOwnerMismatch  bool
		syntheticDeviceExists bool
		validJSON             bool
	}{
		{
			name:                  "Successful frunk open command",
			command:               "frunk/open",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusOK,
			expectedCommandID:     "test-command-id-123",
			expectedStatus:        commands.CommandStatusPending,
			expectedMessage:       "Command successfully submitted for processing",
			syntheticDeviceExists: true,
			validJSON:             true,
		},
		{
			name:                  "Successful trunk open command",
			command:               "trunk/open",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusOK,
			expectedCommandID:     "test-command-id-456",
			expectedStatus:        commands.CommandStatusPending,
			expectedMessage:       "Command successfully submitted for processing",
			syntheticDeviceExists: true,
			validJSON:             true,
		},
		{
			name:                  "Successful doors lock command",
			command:               "doors/lock",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusOK,
			expectedCommandID:     "test-command-id-789",
			expectedStatus:        commands.CommandStatusPending,
			expectedMessage:       "Command successfully submitted for processing",
			syntheticDeviceExists: true,
			validJSON:             true,
		},
		{
			name:                  "Successful doors unlock command",
			command:               "doors/unlock",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusOK,
			expectedCommandID:     "test-command-id-101",
			expectedStatus:        commands.CommandStatusPending,
			expectedMessage:       "Command successfully submitted for processing",
			syntheticDeviceExists: true,
			validJSON:             true,
		},
		{
			name:                  "Successful charge start command",
			command:               "charge/start",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusOK,
			expectedCommandID:     "test-command-id-202",
			expectedStatus:        commands.CommandStatusPending,
			expectedMessage:       "Command successfully submitted for processing",
			syntheticDeviceExists: true,
			validJSON:             true,
		},
		{
			name:                  "Successful charge stop command",
			command:               "charge/stop",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusOK,
			expectedCommandID:     "test-command-id-303",
			expectedStatus:        commands.CommandStatusPending,
			expectedMessage:       "Command successfully submitted for processing",
			syntheticDeviceExists: true,
			validJSON:             true,
		},
		{
			name:                  "Empty command",
			command:               "",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusBadRequest,
			syntheticDeviceExists: true,
			validJSON:             true,
		},
		{
			name:                  "Unsupported command",
			command:               "windows/open",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusBadRequest,
			syntheticDeviceExists: true,
			validJSON:             true,
		},
		{
			name:                  "Inactive subscription",
			command:               "frunk/open",
			subscriptionStatus:    "inactive",
			expectedStatusCode:    fiber.StatusForbidden,
			syntheticDeviceExists: true,
			validJSON:             true,
		},
		{
			name:                  "Command publisher error",
			command:               "frunk/open",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusInternalServerError,
			publishCommandError:   fmt.Errorf("failed to publish to Kafka"),
			syntheticDeviceExists: true,
			validJSON:             true,
		},
		{
			name:                  "Command save error (should still succeed)",
			command:               "frunk/open",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusOK,
			expectedCommandID:     "test-command-id-404",
			expectedStatus:        commands.CommandStatusPending,
			expectedMessage:       "Command successfully submitted for processing",
			saveCommandError:      fmt.Errorf("database error"),
			syntheticDeviceExists: true,
			validJSON:             true,
		},
		{
			name:                  "Vehicle ownership mismatch",
			command:               "frunk/open",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusUnauthorized,
			vehicleOwnerMismatch:  true,
			syntheticDeviceExists: true,
			validJSON:             true,
		},
		{
			name:                  "Synthetic device not found",
			command:               "frunk/open",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusNotFound,
			syntheticDeviceExists: false,
			validJSON:             true,
		},
		{
			name:                  "Invalid JSON",
			command:               "frunk/open",
			subscriptionStatus:    "active",
			expectedStatusCode:    fiber.StatusBadRequest,
			syntheticDeviceExists: true,
			validJSON:             false,
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			// given
			settings, logger, repos := s.createTestDependencies()

			// Determine if we need command mocks
			needsCommandMocks := tc.syntheticDeviceExists && tc.validJSON && tc.command != "" && tc.command != "windows/open" && tc.subscriptionStatus == "active" && !tc.vehicleOwnerMismatch

			// Setup mocks using setupGenericMocks
			config := MockConfig{
				NeedsIdentity:         !tc.vehicleOwnerMismatch,
				VehicleOwnerMismatch:  tc.vehicleOwnerMismatch,
				NeedsCommandPublisher: needsCommandMocks,
				NeedsCommandRepo:      needsCommandMocks && tc.publishCommandError == nil,
				CommandPublisherError: tc.publishCommandError,
				CommandRepoError:      tc.saveCommandError,
				ExpectedCommandID:     tc.expectedCommandID,
			}

			_, _, mockIdentitySvc, _, mockCommandPublisher, mockCommandRepo := s.setupGenericMocks(config)

			// Set command repository in repos if we have one
			if mockCommandRepo != nil {
				repos.Command = mockCommandRepo
			}

			// Create Tesla service
			teslaSvc := service.NewTeslaService(settings, logger, new(cipher.ROT13Cipher), repos, nil, mockIdentitySvc, nil, nil, mockCommandPublisher)

			// Create synthetic device if needed
			var dbVin *models.SyntheticDevice
			if tc.syntheticDeviceExists {
				dbVin = s.createTestSyntheticDeviceWithStatus(teslaSvc.Cipher, tc.subscriptionStatus)
				defer func() {
					_, _ = dbVin.Delete(s.ctx, s.pdb.DBS().Writer)
				}()
			}

			controller := NewTeslaController(settings, logger, teslaSvc, nil, nil)
			app := s.setupTestApp("/v1/tesla/commands/:vehicleTokenId", "POST", controller.SubmitCommand)

			// when
			var requestBody string
			if tc.validJSON {
				requestBody = fmt.Sprintf(`{"command": "%s"}`, tc.command)
			} else {
				requestBody = `{"command": "frunk/open"` // Invalid JSON - missing closing brace
			}

			req, _ := http.NewRequest("POST", fmt.Sprintf("/v1/tesla/commands/%d", vehicleTokenID), strings.NewReader(requestBody))
			req.Header.Set("Content-Type", "application/json")
			assert.NoError(s.T(), test.GenerateJWT(req))

			resp, err := app.Test(req)

			// then
			assert.NoError(s.T(), err)
			assert.Equal(s.T(), tc.expectedStatusCode, resp.StatusCode)

			if tc.expectedStatusCode == fiber.StatusOK {
				s.assertSubmitCommandResponse(resp, tc.expectedCommandID, tc.expectedStatus, tc.expectedMessage)
			}

			// Verify mock expectations
			if mockCommandPublisher != nil {
				mockCommandPublisher.AssertExpectations(s.T())
			}
			if mockCommandRepo != nil {
				mockCommandRepo.AssertExpectations(s.T())
			}
			if tc.validJSON && mockIdentitySvc != nil {
				mockIdentitySvc.AssertExpectations(s.T())
			}
		})
	}
}*/

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

func (s *TeslaControllerTestSuite) createTestDependencies() (*config.Settings, *zerolog.Logger, *repository.Repositories) {
	wallet := common.HexToAddress(walletAddress)
	settings := &config.Settings{MobileAppDevLicense: wallet, DevicesGRPCEndpoint: "localhost:50051"}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})

	vehicleRepo := repository.NewVehicleRepository(&s.pdb, new(cipher.ROT13Cipher), &logger)
	onboardingRepo := repository.NewOnboardingRepository(&s.pdb, &logger)
	mockCredStore := new(test.MockCredStore)

	repos := &repository.Repositories{
		Vehicle:    vehicleRepo,
		Credential: mockCredStore,
		Onboarding: onboardingRepo,
	}

	return settings, &logger, repos
}

func (s *TeslaControllerTestSuite) setupMockIdentityService() *test.MockIdentityAPIService {
	mockIdentitySvc := new(test.MockIdentityAPIService)
	mockVehicle := &mods.Vehicle{
		Owner:   walletAddress,
		TokenID: vehicleTokenID,
		SyntheticDevice: mods.SyntheticDevice{
			Address: "0xabcdef1234567890abcdef1234567890abcdef12",
		},
	}
	mockIdentitySvc.On("FetchVehicleByTokenID", int64(vehicleTokenID)).Return(mockVehicle, nil)
	return mockIdentitySvc
}

func (s *TeslaControllerTestSuite) setupRedisContainer() (testcontainers.Container, *repository.TempCredsStore, error) {
	// Spin up a local Redis container
	redisContainer, err := testcontainers.GenericContainer(s.ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis:latest",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForListeningPort("6379/tcp"),
		},
		Started: true,
	})
	if err != nil {
		return nil, nil, err
	}

	// Get the Redis container's host and port
	redisHost, err := redisContainer.Host(s.ctx)
	if err != nil {
		return nil, nil, err
	}
	redisPort, err := redisContainer.MappedPort(s.ctx, "6379")
	if err != nil {
		return nil, nil, err
	}

	// Create cacheService
	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort.Port())
	cacheService := redis.NewRedisCacheService(false, redis.Settings{
		URL:       redisAddr,
		Password:  "",
		TLS:       false,
		KeyPrefix: "tesla-oracle",
	})

	credStore := &repository.TempCredsStore{
		Cache:  cacheService,
		Cipher: new(cipher.ROT13Cipher),
	}

	return redisContainer, credStore, nil
}

func (s *TeslaControllerTestSuite) setupTestAppForListVehicles(controller *TeslaController) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		// Simulate JWT middleware setting the user in Locals with more comprehensive claims
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
	return app
}

func (s *TeslaControllerTestSuite) assertListVehiclesResponse(resp *http.Response) {
	// Read and parse response body
	bodyBytes, err := io.ReadAll(resp.Body)
	assert.NoError(s.T(), err)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.T().Logf("failed to close response body: %v", err)
		}
	}()

	var responseWrapper CompleteOAuthExchangeResponseWrapper
	err = json.Unmarshal(bodyBytes, &responseWrapper)
	assert.NoError(s.T(), err)

	expectedVehicles := []mods.TeslaVehicleRes{
		{
			VIN:        vin,
			ExternalID: "1",
			Definition: mods.DeviceDefinitionRes{Make: "", Model: "Model 3", Year: 2019, DeviceDefinitionID: "12345"},
		},
	}
	assert.Equal(s.T(), expectedVehicles, responseWrapper.Vehicles)
}

func (s *TeslaControllerTestSuite) setupListVehiclesMocks() (*test.MockIdentityAPIService, *test.MockTeslaFleetAPIService, *test.MockDeviceDefinitionsAPIService) {
	mockIdentitySvc := new(test.MockIdentityAPIService)
	mockTeslaService := new(test.MockTeslaFleetAPIService)
	mockDDService := new(test.MockDeviceDefinitionsAPIService)

	expectedDeviceDefinition := &mods.DeviceDefinition{
		DeviceDefinitionID: "12345",
		Model:              "Model 3",
		Year:               2019,
	}

	teslaVehicles := []core.TeslaVehicle{
		{
			VIN:       vin,
			ID:        1,
			VehicleID: vehicleTokenID,
		},
	}

	signedToken := generateTokenWithClaims()
	expectedResponse := &core.TeslaAuthCodeResponse{
		AccessToken:  signedToken,
		RefreshToken: "mockRefreshToken",
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
		Region:       "NA",
	}

	mockDDService.On("DecodeVin", vin, "USA").Return(&service.DecodeVinResponse{
		DeviceDefinitionID: "12345",
		NewTransactionHash: "0xabc123",
	}, nil)
	mockTeslaService.On("CompleteTeslaAuthCodeExchange", mock.Anything, "testAuthCode", "https://example.com/callback").Return(expectedResponse, nil)
	mockTeslaService.On("GetVehicles", mock.Anything, signedToken).Return(teslaVehicles, nil)
	mockIdentitySvc.On("FetchDeviceDefinitionByID", "12345").Return(expectedDeviceDefinition, nil)

	return mockIdentitySvc, mockTeslaService, mockDDService
}

func (s *TeslaControllerTestSuite) setupTestApp(route string, method string, handler func(*fiber.Ctx) error) *fiber.App {
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
	case "POST":
		app.Post(route, handler)
	case "GET":
		app.Get(route, handler)
	}

	return app
}

func (s *TeslaControllerTestSuite) setupMockServices(fleetStatus *core.VehicleFleetStatus, expectedAction string, limitReached bool) (*test.MockTeslaFleetAPIService, *test.MockDevicesGRPCService) {
	config := MockConfig{
		FleetStatus:  fleetStatus,
		NeedsDevices: expectedAction == service.ActionStartPolling,
	}

	mockTeslaService, _, _, mockDevicesService, _, _ := s.setupGenericMocks(config)

	// Setup action-specific mocks
	switch expectedAction {
	case service.ActionSetTelemetryConfig:
		mockTeslaService.On("SubscribeForTelemetryData", mock.Anything, mock.Anything, vin).Return(nil)
		mockTeslaService.On("GetTelemetrySubscriptionStatus", mock.Anything, mock.Anything, vin).Return(&core.VehicleTelemetryStatus{LimitReached: limitReached}, nil)
	case service.ActionStartPolling:
		mockDevicesService.On("StartTeslaTask", mock.Anything, int64(vehicleTokenID)).Return(nil)
	case service.ActionDummy:
		mockTeslaService.On("GetTelemetrySubscriptionStatus", mock.Anything, mock.Anything, vin).Return(&core.VehicleTelemetryStatus{LimitReached: limitReached}, nil)
	}

	return mockTeslaService, mockDevicesService
}

func (s *TeslaControllerTestSuite) assertSubscriptionStatus(expectedStatus string, vehicleTokenID int) {
	device, err := models.SyntheticDevices(
		models.SyntheticDeviceWhere.VehicleTokenID.EQ(null.NewInt(vehicleTokenID, true))).One(s.ctx, s.pdb.DBS().Reader)
	require.NoError(s.T(), err)

	assert.True(s.T(), device.SubscriptionStatus.Valid)
	assert.Equal(s.T(), expectedStatus, device.SubscriptionStatus.String)
}

func (s *TeslaControllerTestSuite) assertMockCalls(mockTeslaService *test.MockTeslaFleetAPIService, mockDevicesService *test.MockDevicesGRPCService, expectedAction string) {
	switch expectedAction {
	case service.ActionSetTelemetryConfig:
		mockTeslaService.AssertCalled(s.T(), "SubscribeForTelemetryData", mock.Anything, mock.Anything, vin)
		mockTeslaService.AssertExpectations(s.T())
	case service.ActionStartPolling:
		mockDevicesService.AssertCalled(s.T(), "StartTeslaTask", mock.Anything, int64(vehicleTokenID))
	}
}

// Generic mock setup functions to reduce duplication
type MockConfig struct {
	FleetStatus           *core.VehicleFleetStatus
	NeedsCredStore        bool
	NeedsIdentity         bool
	NeedsDevices          bool
	NeedsPartnerToken     bool
	EnableTelemetryStatus bool
	TelemetryStatus       bool
	AccessToken           string
	PartnerToken          string
	NeedsCommandPublisher bool
	NeedsCommandRepo      bool
	CommandPublisherError error
	CommandRepoError      error
	ExpectedCommandID     string
	VehicleOwnerMismatch  bool
}

func (s *TeslaControllerTestSuite) setupGenericMocks(config MockConfig) (*test.MockTeslaFleetAPIService, *test.MockCredStore, *test.MockIdentityAPIService, *test.MockDevicesGRPCService, *test.MockCommandPublisher, *test.MockCommandRepository) {
	mockTeslaService := new(test.MockTeslaFleetAPIService)
	var mockCredStore *test.MockCredStore
	var mockIdentitySvc *test.MockIdentityAPIService
	var mockDevicesService *test.MockDevicesGRPCService
	var mockCommandPublisher *test.MockCommandPublisher
	var mockCommandRepo *test.MockCommandRepository

	// Setup access token (default if not specified)
	accessToken := "mockAccessToken"
	if config.AccessToken != "" {
		accessToken = config.AccessToken
	}

	// Setup credential store if needed
	if config.NeedsCredStore {
		walletAdd := common.HexToAddress(walletAddress)
		mockCredStore = new(test.MockCredStore)
		mockCredStore.On("Retrieve", mock.Anything, walletAdd).Return(&repository.Credential{
			AccessToken: accessToken,
		}, nil)
	}

	// Setup identity service if needed
	if config.NeedsIdentity {
		synthDeviceAddressStr := "0xabcdef1234567890abcdef1234567890abcdef12"
		mockIdentitySvc = new(test.MockIdentityAPIService)
		mockVehicle := &mods.Vehicle{
			Owner:   walletAddress,
			TokenID: vehicleTokenID,
			SyntheticDevice: mods.SyntheticDevice{
				Address: synthDeviceAddressStr,
			},
		}
		mockIdentitySvc.On("FetchVehicleByTokenID", int64(vehicleTokenID)).Return(mockVehicle, nil)
	}

	// Setup devices service if needed
	if config.NeedsDevices {
		mockDevicesService = new(test.MockDevicesGRPCService)
		mockDevicesService.On("StopTeslaTask", mock.Anything, int64(vehicleTokenID)).Return(nil)
	}

	// Setup fleet status if provided
	if config.FleetStatus != nil {
		mockTeslaService.On("VirtualKeyConnectionStatus", mock.Anything, accessToken, vin).Return(config.FleetStatus, nil)
	}

	// Setup default telemetry status for status endpoint (when EnableTelemetryStatus is true)
	if config.EnableTelemetryStatus {
		mockTeslaService.On("GetTelemetrySubscriptionStatus", mock.Anything, accessToken, vin).Return(&core.VehicleTelemetryStatus{
			Configured: config.TelemetryStatus,
		}, nil)
	}

	// Setup partner token if needed
	if config.NeedsPartnerToken {
		partnerToken := "someToken"
		if config.PartnerToken != "" {
			partnerToken = config.PartnerToken
		}
		mockTeslaService.On("GetPartnersToken", mock.Anything).Return(&core.PartnersAccessTokenResponse{
			AccessToken: partnerToken,
			ExpiresIn:   22222,
			TokenType:   "Bearer",
		}, nil)
		mockTeslaService.On("UnSubscribeFromTelemetryData", mock.Anything, partnerToken, vin).Return(nil)
	}

	// Setup command publisher if needed
	if config.NeedsCommandPublisher {
		mockCommandPublisher = new(test.MockCommandPublisher)
		commandID := "test-command-id-123"
		if config.ExpectedCommandID != "" {
			commandID = config.ExpectedCommandID
		}
		if config.CommandPublisherError != nil {
			mockCommandPublisher.On("PublishCommand", mock.Anything, mock.Anything, mock.Anything).Return("", config.CommandPublisherError)
		} else {
			mockCommandPublisher.On("PublishCommand", mock.Anything, mock.Anything, mock.Anything).Return(commandID, nil)
		}
	}

	// Setup command repository if needed
	if config.NeedsCommandRepo {
		mockCommandRepo = new(test.MockCommandRepository)
		if config.CommandRepoError != nil {
			mockCommandRepo.On("SaveCommandRequest", mock.Anything, mock.Anything).Return(config.CommandRepoError)
		} else {
			mockCommandRepo.On("SaveCommandRequest", mock.Anything, mock.Anything).Return(nil)
		}
	}

	// Setup identity service with ownership mismatch if needed
	if config.VehicleOwnerMismatch {
		mockIdentitySvc = new(test.MockIdentityAPIService)
		mockVehicle := &mods.Vehicle{
			Owner:   "0xdifferentowner123456789abcdef123456789abcdef",
			TokenID: vehicleTokenID,
			SyntheticDevice: mods.SyntheticDevice{
				Address: "0xabcdef1234567890abcdef1234567890abcdef12",
			},
		}
		mockIdentitySvc.On("FetchVehicleByTokenID", int64(vehicleTokenID)).Return(mockVehicle, nil)
	}

	return mockTeslaService, mockCredStore, mockIdentitySvc, mockDevicesService, mockCommandPublisher, mockCommandRepo
}

// Convenience wrappers for common patterns
func (s *TeslaControllerTestSuite) setupVirtualKeyStatusMocks() (*test.MockTeslaFleetAPIService, *test.MockCredStore) {
	fleetStatus := &core.VehicleFleetStatus{
		KeyPaired:                      true,
		VehicleCommandProtocolRequired: true,
		NumberOfKeys:                   1,
	}
	mockTeslaService, mockCredStore, _, _, _, _ := s.setupGenericMocks(MockConfig{
		FleetStatus:    fleetStatus,
		NeedsCredStore: true,
	})
	return mockTeslaService, mockCredStore
}

func (s *TeslaControllerTestSuite) setupGetStatusMocks(fleetStatus *core.VehicleFleetStatus) (*test.MockTeslaFleetAPIService, *test.MockCredStore) {
	mockTeslaService, mockCredStore, _, _, _, _ := s.setupGenericMocks(MockConfig{
		FleetStatus: fleetStatus,
	})
	return mockTeslaService, mockCredStore
}

func (s *TeslaControllerTestSuite) setupUnsubscribeMocks() (*test.MockTeslaFleetAPIService, *test.MockDevicesGRPCService, *test.MockIdentityAPIService) {
	mockTeslaService, _, mockIdentitySvc, mockDevicesService, _, _ := s.setupGenericMocks(MockConfig{
		NeedsIdentity:     true,
		NeedsDevices:      true,
		NeedsPartnerToken: true,
	})
	return mockTeslaService, mockDevicesService, mockIdentitySvc
}

// Generic response assertion function
func (s *TeslaControllerTestSuite) assertJSONResponse(resp *http.Response, target interface{}, expectedStatusCode int) {
	err := parseResponse(resp, target)
	s.Require().NoError(err)
	s.Equal(expectedStatusCode, resp.StatusCode)
}

func (s *TeslaControllerTestSuite) assertVirtualKeyStatusResponse(resp *http.Response) {
	var response mods.VirtualKeyStatusResponse
	s.assertJSONResponse(resp, &response, fiber.StatusOK)

	// Assert the response fields
	assert.True(s.T(), response.Added)
	assert.Equal(s.T(), mods.VirtualKeyStatus(1), response.Status)
}

func (s *TeslaControllerTestSuite) assertGetStatusResponse(resp *http.Response, expectedResponse *mods.StatusDecision, expectedStatusCode int) {
	var actualResponse mods.StatusDecision
	s.assertJSONResponse(resp, &actualResponse, expectedStatusCode)

	// Assert the response content
	s.Equal(expectedResponse.Message, actualResponse.Message)
	s.Equal(expectedResponse.Next, actualResponse.Next)
}

// Helper function to assert SubmitCommand response
func (s *TeslaControllerTestSuite) assertSubmitCommandResponse(resp *http.Response, expectedCommandID, expectedStatus, expectedMessage string) {
	var response mods.SubmitCommandResponse
	s.assertJSONResponse(resp, &response, fiber.StatusOK)

	assert.Equal(s.T(), expectedCommandID, response.CommandID)
	assert.Equal(s.T(), expectedStatus, response.Status)
	assert.Equal(s.T(), expectedMessage, response.Message)
}

func (s *TeslaControllerTestSuite) createTestSyntheticDeviceWithStatus(cipher cipher.Cipher, subscriptionStatus string) *models.SyntheticDevice {
	encryptedAccessToken, _ := cipher.Encrypt("mockAccessToken")
	encryptedRefreshToken, _ := cipher.Encrypt("mockRefreshToken")

	currentTime := time.Now()
	accessExpireAt := currentTime.Add(time.Hour)
	refreshExpireAt := currentTime.AddDate(0, 3, 0)

	dbVin := &models.SyntheticDevice{
		Address:           common.HexToAddress("0xabcdef1234567890abcdef1234567890abcdef12").Bytes(),
		Vin:               vin,
		TokenID:           null.NewInt(456, true),
		VehicleTokenID:    null.NewInt(vehicleTokenID, true),
		WalletChildNumber: 111,
		AccessToken:       null.StringFrom(encryptedAccessToken),
		RefreshToken:      null.StringFrom(encryptedRefreshToken),
		AccessExpiresAt:   null.TimeFrom(accessExpireAt.In(time.UTC)),
		RefreshExpiresAt:  null.TimeFrom(refreshExpireAt.In(time.UTC)),
	}

	if subscriptionStatus != "" {
		dbVin.SubscriptionStatus = null.StringFrom(subscriptionStatus)
	}

	require.NoError(s.T(), dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))
	return dbVin
}
