package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfigVEXSources(t *testing.T) {
	dir := t.TempDir()
	content := `{
		"clusterName": "test-cluster",
		"keepLocal": true,
		"vexSources": [
			{"url": "https://vex.example.com/openvex.json"},
			{"url": "https://security.example.com/csaf.json", "format": "CSAF"}
		]
	}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "clusterData.json"), []byte(content), 0o600))

	cfg, err := LoadConfig(dir)
	require.NoError(t, err)
	require.Equal(t, []VEXSourceConfig{
		{URL: "https://vex.example.com/openvex.json", Format: "openvex"},
		{URL: "https://security.example.com/csaf.json", Format: "csaf"},
	}, cfg.VEXSources)
}

func TestLoadConfigRejectsInvalidVEXSources(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "non-HTTPS URL", source: `{"url":"http://vex.example.com/feed.json"}`, want: "absolute HTTPS URL"},
		{name: "unsupported format", source: `{"url":"https://vex.example.com/feed.json","format":"xml"}`, want: "unsupported"},
		{name: "empty URL", source: `{"url":"","format":"openvex"}`, want: "absolute HTTPS URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			content := `{"clusterName":"test-cluster","keepLocal":true,"vexSources":[` + tt.source + `]}`
			require.NoError(t, os.WriteFile(filepath.Join(dir, "clusterData.json"), []byte(content), 0o600))
			_, err := LoadConfig(dir)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.want)
		})
	}
}
