package domain

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestScanStatusJSON_OmitsZeroLifecycleTimestamps(t *testing.T) {
	status := ScanStatus{
		JobID:      "job-queued",
		Endpoint:   "generateSBOM",
		State:      ScanStateQueued,
		Phase:      string(ScanStateQueued),
		AcceptedAt: time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
		UpdatedAt:  time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
	}

	body, err := json.Marshal(status)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	require.NotContains(t, got, "startedAt")
	require.NotContains(t, got, "finishedAt")
}
