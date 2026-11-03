package workers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/riverqueue/river/rivertype"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestHandleErrorLogsEveryKindAndAttempt(t *testing.T) {
	tests := []struct {
		name          string
		kind          string
		attempt       int
		maxAttempts   int
		expectedLevel string
	}{
		{name: "poll will retry", kind: "tesla_legacy_poll", attempt: 1, maxAttempts: 25, expectedLevel: "warn"},
		{name: "poll out of attempts", kind: "tesla_legacy_poll", attempt: 25, maxAttempts: 25, expectedLevel: "error"},
		{name: "mint has one attempt", kind: "onboard", attempt: 1, maxAttempts: 1, expectedLevel: "error"},
		{name: "command will retry", kind: "tesla_command", attempt: 2, maxAttempts: 3, expectedLevel: "warn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			handler := NewTeslaCommandErrorHandler(zerolog.New(&logs), nil)

			job := &rivertype.JobRow{ID: 7, Kind: tt.kind, Attempt: tt.attempt, MaxAttempts: tt.maxAttempts}
			require.Nil(t, handler.HandleError(context.Background(), job, errors.New("boom")))

			var line map[string]any
			require.NoError(t, json.Unmarshal(logs.Bytes(), &line))
			require.Equal(t, tt.expectedLevel, line["level"])
			require.Equal(t, tt.kind, line["jobKind"])
			require.EqualValues(t, 7, line["jobId"])
			require.EqualValues(t, tt.attempt, line["attempt"])
			require.EqualValues(t, tt.maxAttempts, line["maxAttempts"])
			require.Equal(t, "boom", line["error"])
		})
	}
}
