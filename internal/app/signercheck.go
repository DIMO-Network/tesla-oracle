package app

import (
	"github.com/DIMO-Network/tesla-oracle/internal/config"
	"github.com/DIMO-Network/token-exchange-api/pkg/signercheck"
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// SignerCheck builds the middleware that refuses developer JWTs whose license signer has
// been disabled since they were minted (token-exchange-api's SignerCheck). It guards the
// /v1/telemetry routes, which accept the DIMO Mobile license's developer JWTs.
func SignerCheck(settings *config.Settings, checker signercheck.Checker, logger *zerolog.Logger) (fiber.Handler, error) {
	mode, err := signercheck.ParseMode(settings.SignerCheckMode)
	if err != nil {
		return nil, err
	}
	return signercheck.Middleware(signercheck.Config{
		Service: "tesla-oracle",
		Mode:    mode,
		Checker: checker,
		Token:   signercheck.MapClaimsToken("user"),
		Logger:  *logger,
	}), nil
}
