package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"go.opentelemetry.io/otel"
)

// TruffleHogAdapter implements secret scanning using trufflehog as a subprocess
type TruffleHogAdapter struct {
	truffleHogPath string
	scanTimeout    time.Duration
}

// TruffleHogResult represents the JSON output from trufflehog
type TruffleHogResult struct {
	SourceMetadata struct {
		Data struct {
			Docker struct {
				File  string `json:"file"`
				Image string `json:"image"`
				Layer string `json:"layer"`
				Tag   string `json:"tag"`
			} `json:"Docker"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	SourceID              int         `json:"SourceID"`
	SourceType            int         `json:"SourceType"`
	SourceName            string      `json:"SourceName"`
	DetectorType          int         `json:"DetectorType"`
	DetectorName          string      `json:"DetectorName"`
	DetectorDescription   string      `json:"DetectorDescription"`
	DecoderName           string      `json:"DecoderName"`
	Verified              bool        `json:"Verified"`
	VerificationFromCache bool        `json:"VerificationFromCache"`
	Raw                   string      `json:"Raw"`
	RawV2                 string      `json:"RawV2"`
	Redacted              string      `json:"Redacted"`
	ExtraData             interface{} `json:"ExtraData"`
	StructuredData        interface{} `json:"StructuredData"`
}

// NewTruffleHogAdapter initializes the TruffleHogAdapter struct
func NewTruffleHogAdapter(truffleHogPath string, scanTimeout time.Duration) *TruffleHogAdapter {
	if truffleHogPath == "" {
		truffleHogPath = "./trufflehog" // Default to local trufflehog binary
	}
	return &TruffleHogAdapter{
		truffleHogPath: truffleHogPath,
		scanTimeout:    scanTimeout,
	}
}

// ScanImage runs trufflehog as a subprocess to scan the given image for secrets and saves the result as JSON
func (t *TruffleHogAdapter) ScanImage(ctx context.Context, imageTag, outputPath string) ([]TruffleHogResult, error) {
	ctx, span := otel.Tracer("").Start(ctx, "TruffleHogAdapter.ScanImage")
	defer span.End()

	logger.L().Debug("starting trufflehog scan",
		helpers.String("imageTag", imageTag),
		helpers.String("outputPath", outputPath))

	// Create output directory if it doesn't exist
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Prepare trufflehog command with JSON output
	cmd := exec.CommandContext(ctx, t.truffleHogPath, "docker", "--image="+imageTag, "--json", "--no-verification", "--detector-timeout=30s")

	logger.L().Debug("executing trufflehog command",
		helpers.String("command", cmd.String()),
		helpers.String("imageTag", imageTag))

	// Set timeout
	if t.scanTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.scanTimeout)
		defer cancel()
		cmd = exec.CommandContext(ctx, t.truffleHogPath, "docker", "--image="+imageTag, "--json", "--no-verification", "--detector-timeout=30s")
	}

	// Capture output
	output, err := cmd.Output()
	if err != nil {
		// Check if it's an exit error (which is normal for trufflehog when no secrets found)
		if exitErr, ok := err.(*exec.ExitError); ok {
			// TruffleHog exits with code 183 when secrets are found, 0 when no secrets found
			if exitErr.ExitCode() == 0 {
				// No secrets found, which is not an error
				logger.L().Debug("trufflehog scan completed - no secrets found",
					helpers.String("imageTag", imageTag))
				return []TruffleHogResult{}, nil
			} else if exitErr.ExitCode() == 183 {
				// Secrets found, this is expected behavior
				logger.L().Debug("trufflehog scan completed - secrets found",
					helpers.String("imageTag", imageTag))
				// Continue to parse the output
			} else {
				// Other error
				return nil, fmt.Errorf("trufflehog command failed with exit code %d: %w", exitErr.ExitCode(), err)
			}
		} else {
			return nil, fmt.Errorf("trufflehog command failed: %w", err)
		}
	}

	// Parse the JSON output (trufflehog outputs one JSON object per line)
	results, err := t.parseTruffleHogOutput(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trufflehog output: %w", err)
	}

	// Save results to file only if there are results
	if len(results) > 0 {
		if err := t.saveResultsToFile(results, outputPath); err != nil {
			return nil, fmt.Errorf("failed to save results to file: %w", err)
		}
	} else {
		// Save empty array to indicate no secrets found
		if err := t.saveResultsToFile([]TruffleHogResult{}, outputPath); err != nil {
			return nil, fmt.Errorf("failed to save empty results to file: %w", err)
		}
	}

	logger.L().Debug("trufflehog scan completed",
		helpers.String("imageTag", imageTag),
		helpers.Int("secretsFound", len(results)))

	return results, nil
}

// parseTruffleHogOutput parses the JSON output from trufflehog (one JSON object per line)
func (t *TruffleHogAdapter) parseTruffleHogOutput(output []byte) ([]TruffleHogResult, error) {
	var results []TruffleHogResult

	// If output is empty, return empty results
	if len(output) == 0 {
		return results, nil
	}

	// Split output by lines
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result TruffleHogResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			logger.L().Warning("failed to parse trufflehog JSON line",
				helpers.Error(err),
				helpers.String("line", line))
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// saveResultsToFile saves the results to a JSON file
func (t *TruffleHogAdapter) saveResultsToFile(results []TruffleHogResult, outputPath string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results to JSON: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write results to file: %w", err)
	}

	return nil
}

// Version returns the trufflehog version
func (t *TruffleHogAdapter) Version() string {
	cmd := exec.Command(t.truffleHogPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return string(output)
}
