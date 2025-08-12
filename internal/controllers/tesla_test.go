package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/DIMO-Network/shared/pkg/redis"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/shared/pkg/cipher"
	"github.com/DIMO-Network/shared/pkg/db"
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
	// given
	ownerAdd := "0x1234567890abcdef1234567890abcdef12345678"
	synthDeviceAddressStr := "0xabcdef1234567890abcdef1234567890abcdef12"
	synthDeviceAddress := common.HexToAddress(synthDeviceAddressStr)
	walletAddress := common.HexToAddress(ownerAdd)

	dbVin := models.SyntheticDevice{
		Address:           synthDeviceAddress.Bytes(),
		Vin:               vin,
		TokenID:           null.NewInt(456, true),
		VehicleTokenID:    null.NewInt(vehicleTokenID, true),
		WalletChildNumber: 111,
	}

	require.NoError(s.T(), dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

	// Define the expected input and output
	authCode := "testAuthCode"
	redirectURI := "https://example.com/callback"
	expectedResponse := &service.TeslaAuthCodeResponse{
		AccessToken:  "mockAccessToken",
		RefreshToken: "mockRefreshToken",
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
		Region:       "NA",
	}

	// when
	mockIdentitySvc := new(test.MockIdentityAPIService)
	mockVehicle := &mods.Vehicle{
		Owner: ownerAdd,
		SyntheticDevice: mods.SyntheticDevice{
			Address: synthDeviceAddressStr,
		},
	}
	mockIdentitySvc.On("FetchVehicleByTokenID", int64(vehicleTokenID)).Return(mockVehicle, nil)

	mockCredStore := new(test.MockCredStore)
	expectedCredentials := &service.Credential{
		AccessToken:   "mockAccessToken",
		RefreshToken:  "mockRefreshToken",
		AccessExpiry:  time.Now().Add(time.Hour),
		RefreshExpiry: time.Now().AddDate(0, 3, 0),
	}
	mockCredStore.On("EncryptTokens", mock.Anything, mock.Anything).Return(expectedCredentials, nil)

	mockTeslaService := new(MockTeslaFleetAPIService)

	//mockCredStore.On("Retrieve", mock.Anything, walletAddress).Return(cred, nil)
	mockTeslaService.On("SubscribeForTelemetryData", mock.Anything, expectedResponse.AccessToken, vin).Return(nil)
	mockTeslaService.On("CompleteTeslaAuthCodeExchange", mock.Anything, authCode, redirectURI).Return(expectedResponse, nil)

	settings := config.Settings{MobileAppDevLicense: walletAddress, DevicesGRPCEndpoint: "localhost:50051"}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	controller := NewTeslaController(&settings, &logger, mockTeslaService, nil, mockIdentitySvc, mockCredStore, nil, &s.pdb)

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		// Simulate JWT middleware setting the user in Locals
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": ownerAdd,
		})
		c.Locals("user", token)
		return c.Next()
	})
	app.Use(helpers.NewWalletMiddleware())
	app.Post("/v1/tesla/telemetry/subscribe/:vehicleTokenId", controller.TelemetrySubscribe)

	// Create the request body
	requestBody := `{
		"authorizationCode": "testAuthCode",
		"redirectUri": "https://example.com/callback"
	}`

	req, _ := http.NewRequest(
		"POST",
		"/v1/tesla/telemetry/subscribe/789",
		strings.NewReader(requestBody),
	)
	req.Header.Set("Content-Type", "application/json")

	// token
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
	assert.Equal(s.T(), "active", device.SubscriptionStatus.String)

	mockCredStore.AssertExpectations(s.T())
	mockTeslaService.AssertExpectations(s.T())
}

func (s *TeslaControllerTestSuite) TestTelemetrySubscribeNoBody() {
	// given
	ownerAdd := "0x1234567890abcdef1234567890abcdef12345678"
	synthDeviceAddressStr := "0xabcdef1234567890abcdef1234567890abcdef12"
	synthDeviceAddress := common.HexToAddress(synthDeviceAddressStr)
	walletAddress := common.HexToAddress(ownerAdd)

	dbVin := models.SyntheticDevice{
		Address:           synthDeviceAddress.Bytes(),
		Vin:               vin,
		TokenID:           null.NewInt(456, true),
		VehicleTokenID:    null.NewInt(vehicleTokenID, true),
		WalletChildNumber: 111,
	}

	require.NoError(s.T(), dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

	// when
	mockTeslaService := new(MockTeslaFleetAPIService)

	settings := config.Settings{MobileAppDevLicense: walletAddress, DevicesGRPCEndpoint: "localhost:50051"}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	controller := NewTeslaController(&settings, &logger, mockTeslaService, nil, nil, nil, nil, &s.pdb)

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		// Simulate JWT middleware setting the user in Locals
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": ownerAdd,
		})
		c.Locals("user", token)
		return c.Next()
	})
	app.Use(helpers.NewWalletMiddleware())
	app.Post("/v1/tesla/telemetry/subscribe/:vehicleTokenId", controller.TelemetrySubscribe)

	// Create the request body
	emptyBody := ""

	req, _ := http.NewRequest(
		"POST",
		"/v1/tesla/telemetry/subscribe/789",
		strings.NewReader(emptyBody),
	)
	req.Header.Set("Content-Type", "application/json")

	// token
	err := test.GenerateJWT(req)
	assert.NoError(s.T(), err)

	// then
	resp, err := app.Test(req)

	// verify
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), fiber.StatusBadRequest, resp.StatusCode)

	// Query the database to verify subscription status
	device, err := models.SyntheticDevices(
		models.SyntheticDeviceWhere.VehicleTokenID.EQ(null.NewInt(vehicleTokenID, true))).One(s.ctx, s.pdb.DBS().Reader)
	require.NoError(s.T(), err)

	// Assert that the subscription status is set and not empty
	assert.True(s.T(), device.SubscriptionStatus.Valid)
	assert.Equal(s.T(), "pending", device.SubscriptionStatus.String)
}

func (s *TeslaControllerTestSuite) TestTelemetrySubscribeNoAuthCode() {
	// given
	ownerAdd := "0x1234567890abcdef1234567890abcdef12345678"
	synthDeviceAddressStr := "0xabcdef1234567890abcdef1234567890abcdef12"
	synthDeviceAddress := common.HexToAddress(synthDeviceAddressStr)
	walletAddress := common.HexToAddress(ownerAdd)

	dbVin := models.SyntheticDevice{
		Address:           synthDeviceAddress.Bytes(),
		Vin:               vin,
		TokenID:           null.NewInt(456, true),
		VehicleTokenID:    null.NewInt(vehicleTokenID, true),
		WalletChildNumber: 111,
	}

	require.NoError(s.T(), dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

	// when
	mockTeslaService := new(MockTeslaFleetAPIService)

	settings := config.Settings{MobileAppDevLicense: walletAddress, DevicesGRPCEndpoint: "localhost:50051"}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	controller := NewTeslaController(&settings, &logger, mockTeslaService, nil, nil, nil, nil, &s.pdb)

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		// Simulate JWT middleware setting the user in Locals
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": ownerAdd,
		})
		c.Locals("user", token)
		return c.Next()
	})
	app.Use(helpers.NewWalletMiddleware())
	app.Post("/v1/tesla/telemetry/subscribe/:vehicleTokenId", controller.TelemetrySubscribe)

	// Create the request body
	noAuthCodeBody := `{
		"redirectUri": "https://example.com/callback"
	}`

	req, _ := http.NewRequest(
		"POST",
		"/v1/tesla/telemetry/subscribe/789",
		strings.NewReader(noAuthCodeBody),
	)
	req.Header.Set("Content-Type", "application/json")

	// token
	err := test.GenerateJWT(req)
	assert.NoError(s.T(), err)

	// then
	resp, err := app.Test(req)

	// verify
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), fiber.StatusBadRequest, resp.StatusCode)

	// Query the database to verify subscription status
	device, err := models.SyntheticDevices(
		models.SyntheticDeviceWhere.VehicleTokenID.EQ(null.NewInt(vehicleTokenID, true))).One(s.ctx, s.pdb.DBS().Reader)
	require.NoError(s.T(), err)

	// Assert that the subscription status is set and not empty
	assert.True(s.T(), device.SubscriptionStatus.Valid)
	assert.Equal(s.T(), "pending", device.SubscriptionStatus.String)
}

func (s *TeslaControllerTestSuite) TestTelemetryUnSubscribe() {
	// given
	ownerAdd := "0x1234567890abcdef1234567890abcdef12345678"
	synthDeviceAddressStr := "0xabcdef1234567890abcdef1234567890abcdef12"
	synthDeviceAddress := common.HexToAddress(synthDeviceAddressStr)
	walletAddress := common.HexToAddress(ownerAdd)

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
		Owner:   ownerAdd,
		TokenID: vehicleTokenID,
		SyntheticDevice: mods.SyntheticDevice{
			Address: synthDeviceAddressStr,
		},
	}
	mockIdentitySvc.On("FetchVehicleByTokenID", int64(vehicleTokenID)).Return(mockVehicle, nil)
	mockCredStore := new(test.MockCredStore)
	mockTeslaService := new(MockTeslaFleetAPIService)

	mockTeslaService.On("GetPartnersToken", mock.Anything).Return(&service.PartnersAccessTokenResponse{
		AccessToken: "someToken",
		ExpiresIn:   22222,
		TokenType:   "Bearer",
	},
		nil,
	)
	mockTeslaService.On("UnSubscribeFromTelemetryData", mock.Anything, "someToken", vin).Return(nil)

	// Mock the DevicesGRPCService
	mockDevicesService := new(MockDevicesGRPCService)
	mockDevicesService.On("StopTeslaTask", mock.Anything, int64(vehicleTokenID)).Return(nil)

	// Initialize the controller
	settings := config.Settings{MobileAppDevLicense: walletAddress, DevicesGRPCEndpoint: "localhost:50051"}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	controller := NewTeslaController(&settings, &logger, mockTeslaService, nil, mockIdentitySvc, mockCredStore, nil, &s.pdb)
	controller.devicesService = mockDevicesService

	// Set up the Fiber app
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		// Simulate JWT middleware setting the user in Locals
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": "0x1234567890abcdef1234567890abcdef12345678",
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
}

func (s *TeslaControllerTestSuite) TestListVehicles() {
	// given
	synthDeviceAddressStr := "0xabcdef1234567890abcdef1234567890abcdef12"
	synthDeviceAddress := common.HexToAddress(synthDeviceAddressStr)
	dbVin := models.SyntheticDevice{
		Address:           synthDeviceAddress.Bytes(),
		Vin:               vin,
		TokenID:           null.NewInt(456, true),
		VehicleTokenID:    null.NewInt(vehicleTokenID, true),
		WalletChildNumber: 111,
	}

	require.NoError(s.T(), dbVin.Insert(s.ctx, s.pdb.DBS().Writer, boil.Infer()))

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
	defer redisContainer.Terminate(s.ctx)

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
	defer redisClient.Close()

	// Create cacheService
	cacheService := redis.NewRedisCacheService(false, redis.Settings{
		URL:       redisAddr,
		Password:  "",
		TLS:       false,
		KeyPrefix: "tesla-oracle",
	})

	// Create TempCredsStore using cacheService
	credStore := service.TempCredsStore{
		Cache:  cacheService,
		Cipher: new(cipher.ROT13Cipher), // Example cipher
	}

	// Mock other dependencies
	signedToken, done := generateTokenWithClaims(err)
	if done {
		return
	}

	mockIdentitySvc := new(test.MockIdentityAPIService)
	mockTeslaService := new(MockTeslaFleetAPIService)
	authCode := "testAuthCode"
	redirectURI := "https://example.com/callback"
	expectedResponse := &service.TeslaAuthCodeResponse{
		AccessToken:  signedToken,
		RefreshToken: "mockRefreshToken",
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
		Region:       "NA",
	}

	// Define expected vehicles
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

	mockDDService := new(MockDeviceDefinitionsAPIService)

	// Define the mock behavior
	mockDDService.On("DecodeVin", "1HGCM82633A123456", "USA").Return(&service.DecodeVinResponse{
		DeviceDefinitionID: "12345",
		NewTransactionHash: "0xabc123",
	}, nil)

	mockTeslaService.On("CompleteTeslaAuthCodeExchange", mock.Anything, authCode, redirectURI).Return(expectedResponse, nil)
	mockTeslaService.On("GetVehicles", mock.Anything, signedToken).Return(teslaVehicles, nil)
	expectedDeviceDefinition := &mods.DeviceDefinition{
		DeviceDefinitionID: "12345",
		Model:              "Model 3",
		Year:               2019,
	}
	mockIdentitySvc.On("FetchDeviceDefinitionByID", "12345").Return(expectedDeviceDefinition, nil)

	// Initialize the controller
	settings := config.Settings{DevicesGRPCEndpoint: "localhost:50051"}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr})
	ons := service.NewOnboardingService(&s.pdb, &logger)
	controller := NewTeslaController(&settings, &logger, mockTeslaService, mockDDService, mockIdentitySvc, &credStore, ons, &s.pdb)

	// Set up the Fiber app
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		// Simulate JWT middleware setting the user in Locals
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"ethereum_address": "0x1234567890abcdef1234567890abcdef12345678",
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

	// Create the request body
	requestBody := `{
		"authorizationCode": "testAuthCode",
		"redirectUri": "https://example.com/callback"
	}`
	// Create a test HTTP request
	req, _ := http.NewRequest("POST", "/v1/tesla/vehicles", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")

	// Generate a valid JWT token
	err = generateJWT(req)
	assert.NoError(s.T(), err)

	// Execute the request
	resp, err := app.Test(req)

	// Verify the response
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), fiber.StatusOK, resp.StatusCode)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}
	defer resp.Body.Close()

	var responseWrapper CompleteOAuthExchangeResponseWrapper
	err = json.Unmarshal(bodyBytes, &responseWrapper)
	assert.NoError(s.T(), err)

	// Assert the response matches the expected vehicles
	assert.Equal(s.T(), expectedVehicles, responseWrapper.Vehicles)

	cachedVehicles, err := cacheService.Get(s.ctx, "credentials_0x1234567890AbcdEF1234567890aBcdef12345678").Result()
	assert.NoError(s.T(), err)
	assert.NotEmpty(s.T(), cachedVehicles)

	// Verify mock expectations
	mockIdentitySvc.AssertExpectations(s.T())
	mockTeslaService.AssertExpectations(s.T())
}

func generateTokenWithClaims(err error) (string, bool) {
	secretKey := []byte("your-secret-key")

	// Define the claims for the token
	claims := jwt.MapClaims{
		"ethereum_address": "0x1234567890AbcdEF1234567890aBcdef12345678",
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
		return "", true
	}
	return signedToken, false
}

func generateJWT(req *http.Request) error {
	// Define the secret key for signing the token
	secretKey := []byte("your-secret-key")

	// Create claims with the required `ethereum_address`
	claims := jwt.MapClaims{
		"ethereum_address": "0x1234567890abcdef1234567890abcdef12345678", // Valid Ethereum address
		"exp":              time.Now().Add(time.Hour).Unix(),             // Token expiration time
	}

	// Create a new token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		fmt.Println("Error signing token:", err)
		return err
	}

	fmt.Println("Valid Token:", signedToken)
	req.Header.Set("Authorization", "Bearer "+signedToken)
	return nil
}

// MockCredStore is a mock implementation of the CredStore interface.
type MockCredStore struct {
	mock.Mock
}

func (m *MockCredStore) Retrieve(ctx context.Context, user common.Address) (*service.Credential, error) {
	args := m.Called(ctx, user)
	return args.Get(0).(*service.Credential), args.Error(1)
}

func (m *MockCredStore) EncryptTokens(credential *service.Credential) (*service.Credential, error) {
	args := m.Called(credential)
	return args.Get(0).(*service.Credential), args.Error(1)
}

func (m *MockCredStore) RetrieveWithTokensEncrypted(ctx context.Context, user common.Address) (*service.Credential, error) {
	args := m.Called(ctx, user)
	return args.Get(0).(*service.Credential), args.Error(1)
}

func (m *MockCredStore) Store(ctx context.Context, user common.Address, cred *service.Credential) error {
	args := m.Called(ctx, user, cred)
	return args.Error(0)
}

// MockTeslaFleetAPIService is a mock implementation of the TeslaFleetAPIService interface.
type MockTeslaFleetAPIService struct {
	mock.Mock
}

func (m *MockTeslaFleetAPIService) GetPartnersToken(ctx context.Context) (*service.PartnersAccessTokenResponse, error) {
	args := m.Called(ctx)
	if args.Get(0) != nil {
		return args.Get(0).(*service.PartnersAccessTokenResponse), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockTeslaFleetAPIService) CompleteTeslaAuthCodeExchange(ctx context.Context, authCode, redirectURI string) (*service.TeslaAuthCodeResponse, error) {
	args := m.Called(ctx, authCode, redirectURI)
	if args.Get(0) != nil {
		return args.Get(0).(*service.TeslaAuthCodeResponse), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockTeslaFleetAPIService) GetVehicles(ctx context.Context, token string) ([]service.TeslaVehicle, error) {
	args := m.Called(ctx, token)
	if args.Get(0) != nil {
		return args.Get(0).([]service.TeslaVehicle), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockTeslaFleetAPIService) GetVehicle(ctx context.Context, token string, vehicleID int) (*service.TeslaVehicle, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockTeslaFleetAPIService) WakeUpVehicle(ctx context.Context, token string, vehicleID int) error {
	//TODO implement me
	panic("implement me")
}

func (m *MockTeslaFleetAPIService) VirtualKeyConnectionStatus(ctx context.Context, token, vin string) (*service.VehicleFleetStatus, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockTeslaFleetAPIService) UnSubscribeFromTelemetryData(ctx context.Context, token, vin string) error {
	args := m.Called(ctx, token, vin)
	return args.Error(0)
}

func (m *MockTeslaFleetAPIService) GetTelemetrySubscriptionStatus(ctx context.Context, token, vin string) (*service.VehicleTelemetryStatus, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockTeslaFleetAPIService) SubscribeForTelemetryData(ctx context.Context, accessToken, vin string) error {
	args := m.Called(ctx, accessToken, vin)
	return args.Error(0)
}

// MockDevicesGRPCService is a mock implementation of the DevicesGRPCService interface.
type MockDevicesGRPCService struct {
	mock.Mock
}

func (m *MockDevicesGRPCService) StopTeslaTask(ctx context.Context, tokenID int64) error {
	args := m.Called(ctx, tokenID)
	return args.Error(0)
}

func (m *MockDevicesGRPCService) Close() error {
	args := m.Called()
	return args.Error(0)
}

type MockDeviceDefinitionsAPIService struct {
	mock.Mock
}

func (m *MockDeviceDefinitionsAPIService) DecodeVin(vin, countryCode string) (*service.DecodeVinResponse, error) {
	args := m.Called(vin, countryCode)
	if args.Get(0) != nil {
		return args.Get(0).(*service.DecodeVinResponse), args.Error(1)
	}
	return nil, args.Error(1)
}
