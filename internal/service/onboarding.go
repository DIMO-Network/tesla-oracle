package service

import (
	"github.com/rs/zerolog"
)

type OnboardingService struct {
	logger *zerolog.Logger
}

// NewOnboardingService creates a new instance of OnboardingService.
func NewOnboardingService(logger *zerolog.Logger) *OnboardingService {
	return &OnboardingService{
		logger: logger,
	}
}

// This service now focuses on business logic only.
