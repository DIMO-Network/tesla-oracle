package helpers

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

const walletKey = "wallet"

// NewWalletMiddleware returns a middleware that check if the wallet in JWT is allowed to access
// Requires JWT middleware to be executed first
func NewWalletMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		walletAddress, err := GetJWTEthAddr(c)
		if err != nil {
			return err
		}

		c.Locals(walletKey, walletAddress)
		return c.Next()
	}
}

func GetWallet(c *fiber.Ctx) common.Address {
	return c.Locals(walletKey).(common.Address)
}

const ethClaim = "ethereum_address"

var zeroAddr common.Address

// GetJWTEthAddr tries to extract an Ethereum address out of the client's JWT.
// If it fails to do so, then it returns a Fiber error that is safe and appropriate
// to return to the client.
func GetJWTEthAddr(c *fiber.Ctx) (common.Address, error) {
	token := c.Locals("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims) // These can't fail!

	ethAddrAny, ok := claims[ethClaim]
	if !ok {
		return zeroAddr, fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Missing claim %s.", ethClaim))
	}

	ethAddrStr, ok := ethAddrAny.(string)
	if !ok {
		return zeroAddr, fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Claim %s had unexpected type %T.", ethClaim, ethAddrAny))
	}

	if !common.IsHexAddress(ethAddrStr) {
		return zeroAddr, fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Claim %s is not a valid Ethereum address.", ethClaim))
	}

	return common.HexToAddress(ethAddrStr), nil
}

func GetLogger(c *fiber.Ctx, d *zerolog.Logger) *zerolog.Logger {
	m := c.Locals("logger")
	if m == nil {
		return d
	}

	l, ok := m.(*zerolog.Logger)
	if !ok {
		return d
	}

	return l
}
