package service

import (
	"testing"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
)

// TestOnboardingArgsInsertOpts: SubmitMintDataForVins inserts OnboardingArgs with
// nil options, so River takes the job's max attempts from the args type. Without
// InsertOpts that was River's default of 25, and a mint that failed after its
// transaction landed on chain was retried: a second vehicle NFT and SD.
func TestOnboardingArgsInsertOpts(t *testing.T) {
	var args river.JobArgs = OnboardingArgs{}
	withOpts, ok := args.(river.JobArgsWithInsertOpts)
	require.True(t, ok, "OnboardingArgs must set its own InsertOpts")
	require.Equal(t, 1, withOpts.InsertOpts().MaxAttempts)
}
