package app

import (
	"errors"
	"os"
	"strconv"

	"github.com/DIMO-Network/go-transactions"
	"github.com/DIMO-Network/shared/pkg/middleware/metrics"
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers"
	"github.com/DIMO-Network/tesla-oracle/internal/controllers/helpers"
	"github.com/DIMO-Network/tesla-oracle/internal/repository"
	"github.com/DIMO-Network/tesla-oracle/internal/service"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/rs/zerolog"
)

func App(
	settings *config.Settings,
	logger *zerolog.Logger,
	identitySvc service.IdentityAPIService,
	onboardingSvc *service.OnboardingService,
	riverClient *river.Client[pgx.Tx],
	ws service.SDWalletsAPI,
	tr *transactions.Client,
	repositories *repository.Repositories,
	teslaService *service.TeslaService,
) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return ErrorHandler(c, err, logger)
		},
		DisableStartupMessage: true,
		ReadBufferSize:        16000,
		BodyLimit:             5 * 1024 * 1024,
	})
	app.Use(metrics.HTTPMetricsMiddleware)

	app.Use(fiberrecover.New(fiberrecover.Config{
		Next:              nil,
		EnableStackTrace:  true,
		StackTraceHandler: nil,
	}))

	if settings.Environment == "local" {
		app.Use(cors.New(cors.Config{
			AllowOrigins:     "*",
			AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
			AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
			AllowCredentials: false,
		}))
	} else {
		app.Use(cors.New(cors.Config{
			AllowOrigins:     "https://localdev.dimo.org:8080",
			AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
			AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
			AllowCredentials: true,
		}))
	}

	// serve static content for production
	app.Get("/", loadStaticIndex)

	staticConfig := fiber.Static{
		Compress: true,
		MaxAge:   0,
		Index:    "index.html",
	}

	app.Static("/", "./dist", staticConfig)

	// application routes
	app.Get("/health", healthCheck)

	// Initialize controllers with services
	teslaCtrl := controllers.NewTeslaController(settings, logger, teslaService)
	onboardCtrl := controllers.NewVehicleOnboardController(settings, logger, identitySvc, onboardingSvc, riverClient, ws, tr, repositories)

	jwtAuth := jwtware.New(jwtware.Config{
		JWKSetURLs: []string{settings.JwtKeySetURL},
	})

	walletMdw := helpers.NewWalletMiddleware()

	// add v1 swagger to align with other services
	app.Get("/v1/swagger/*", swagger.HandlerDefault)
	app.Get("/swagger/*", swagger.HandlerDefault)

	teslaGroup := app.Group("/v1/tesla", jwtAuth, walletMdw)
	teslaGroup.Get("/settings", teslaCtrl.GetSettings)
	teslaGroup.Post("/vehicles", teslaCtrl.ListVehicles)
	teslaGroup.Get("/virtual-key", teslaCtrl.GetVirtualKeyStatus)
	teslaGroup.Get("/:vehicleTokenId/status", teslaCtrl.GetStatus)
	teslaGroup.Post("/:vehicleTokenId/start", teslaCtrl.StartDataFlow)

	vehicleGroup := app.Group("/v1/vehicle", jwtAuth, walletMdw)
	vehicleGroup.Post("/verify", onboardCtrl.VerifyVins)
	vehicleGroup.Get("/mint/status", onboardCtrl.GetMintStatusForVins)
	vehicleGroup.Get("/mint", onboardCtrl.GetMintDataForVins)
	vehicleGroup.Post("/mint", onboardCtrl.SubmitMintDataForVins)
	vehicleGroup.Post("/finalize", onboardCtrl.FinalizeOnboarding)

	telemetryGroup := app.Group("/v1/tesla/telemetry", jwtAuth, walletMdw)
	telemetryGroup.Post("/subscribe/:vehicleTokenId", teslaCtrl.TelemetrySubscribe)
	telemetryGroup.Post("/unsubscribe/:vehicleTokenId", teslaCtrl.UnsubscribeTelemetry)

	return app
}

func healthCheck(c *fiber.Ctx) error {
	res := map[string]interface{}{
		"data": "Server is up and running",
	}

	err := c.JSON(res)

	if err != nil {
		return err
	}

	return nil
}

func loadStaticIndex(ctx *fiber.Ctx) error {
	dat, err := os.ReadFile("dist/index.html")
	if err != nil {
		return err
	}
	ctx.Set("Content-Type", "text/html; charset=utf-8")
	return ctx.Status(fiber.StatusOK).Send(dat)
}

// ErrorHandler custom handler to log recovered errors using our logger and return json instead of string
func ErrorHandler(c *fiber.Ctx, err error, logger *zerolog.Logger) error {
	code := fiber.StatusInternalServerError // HTTP 500 by default

	var e *fiber.Error
	isFiberErr := errors.As(err, &e)
	if isFiberErr {
		// Override status code if fiber.Error type
		code = e.Code
	}
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	codeStr := strconv.Itoa(code)

	if code != fiber.StatusNotFound {
		logger.Err(err).Str("httpStatusCode", codeStr).
			Str("httpMethod", c.Method()).
			Str("httpPath", c.Path()).
			Msg("caught an error from http request")
	}

	return c.Status(code).JSON(ErrorRes{
		Code:    code,
		Message: err.Error(),
	})
}

type ErrorRes struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
