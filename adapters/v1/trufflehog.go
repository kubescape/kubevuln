package v1

import (
	"bufio"
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
	"github.com/kubescape/kubevuln/core/domain"
	"go.opentelemetry.io/otel"
)

// TruffleHogAdapter implements secret scanning using trufflehog as a subprocess
type TruffleHogAdapter struct {
	truffleHogPath  string
	scanTimeout     time.Duration
	storage         *ScanReportStorageAdapter
	imageDownloader *ImageDownloader
}

// TruffleHogResult represents a single secret found by trufflehog
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
	SourceID              int    `json:"SourceID"`
	SourceType            int    `json:"SourceType"`
	SourceName            string `json:"SourceName"`
	DetectorType          int    `json:"DetectorType"`
	DetectorName          string `json:"DetectorName"`
	DetectorDescription   string `json:"DetectorDescription"`
	DecoderName           string `json:"DecoderName"`
	Verified              bool   `json:"Verified"`
	VerificationFromCache bool   `json:"VerificationFromCache"`
	Raw                   string `json:"Raw"`
	RawV2                 string `json:"RawV2"`
	Redacted              string `json:"Redacted"`
	ExtraData             struct {
		Line    int    `json:"line"`
		File    string `json:"file"`
		Symlink string `json:"symlink"`
	} `json:"ExtraData"`
	StructuredData struct {
		Line    int    `json:"line"`
		File    string `json:"file"`
		Symlink string `json:"symlink"`
	} `json:"StructuredData"`
}

// NewTruffleHogAdapter initializes the TruffleHogAdapter struct
func NewTruffleHogAdapter(truffleHogPath string, scanTimeout time.Duration, storage *ScanReportStorageAdapter) *TruffleHogAdapter {
	if truffleHogPath == "" {
		truffleHogPath = "./trufflehog" // Default to local trufflehog binary
	}
	return &TruffleHogAdapter{
		truffleHogPath:  truffleHogPath,
		scanTimeout:     scanTimeout,
		storage:         storage,
		imageDownloader: NewImageDownloader(1024*1024*1024*2, scanTimeout), // 2GB max image size
	}
}

// ScanImage downloads an image and runs trufflehog analysis on it
func (t *TruffleHogAdapter) ScanImage(ctx context.Context, imageID, imageTag string, registryOptions domain.RegistryOptions, imageName, jobID, outputPath string) ([]TruffleHogResult, error) {
	ctx, span := otel.Tracer("").Start(ctx, "TruffleHogAdapter.ScanImage")
	defer span.End()

	logger.L().Debug("starting trufflehog scan with image download",
		helpers.String("imageID", imageID),
		helpers.String("imageTag", imageTag),
		helpers.String("imageName", imageName),
		helpers.String("jobID", jobID))

	// Download the image as a tarball first
	downloadResult, err := t.imageDownloader.DownloadImageAsTarball(ctx, imageID, imageTag, registryOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to download image for trufflehog scan: %w", err)
	}
	defer downloadResult.Cleanup()

	logger.L().Debug("image downloaded for trufflehog scan",
		helpers.String("tarballPath", downloadResult.TarballPath),
		helpers.Int("imageSize", int(downloadResult.ImageSize)))

	// Now run trufflehog scan on the downloaded tarball
	results, err := t.ScanTarball(ctx, downloadResult.TarballPath, imageName, jobID, outputPath)
	if err != nil {
		return nil, err
	}

	// Save to unified storage with correct imageTag (CRD or file)
	if t.storage != nil {
		if err := t.storage.SaveScanReport(ctx, imageTag, imageName, jobID, nil, results, outputPath); err != nil {
			logger.L().Error("failed to save trufflehog report to storage with correct imageTag", helpers.Error(err))
		}
	}

	return results, nil
}

// ScanTarball runs trufflehog as a subprocess to scan the given tarball for secrets and saves the result
func (t *TruffleHogAdapter) ScanTarball(ctx context.Context, tarballPath, imageName, jobID, outputPath string) ([]TruffleHogResult, error) {
	ctx, span := otel.Tracer("").Start(ctx, "TruffleHogAdapter.ScanTarball")
	defer span.End()

	logger.L().Debug("starting trufflehog scan on tarball",
		helpers.String("tarballPath", tarballPath),
		helpers.String("imageName", imageName),
		helpers.String("jobID", jobID))

	// Create output directory if it doesn't exist
	if outputPath != "" {
		outputDir := filepath.Dir(outputPath)
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Prepare trufflehog command with JSON output for tarball
	// Use file:// prefix for local tarball files
	cmd := exec.CommandContext(ctx, t.truffleHogPath, "docker", "--image=file://"+tarballPath, "--json", "--no-verification", "--detector-timeout=30s", "--no-update")

	logger.L().Debug("executing trufflehog command on tarball",
		helpers.String("command", cmd.String()),
		helpers.String("tarballPath", tarballPath))

	// Set timeout
	if t.scanTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.scanTimeout)
		defer cancel()
		cmd = exec.CommandContext(ctx, t.truffleHogPath, "docker", "--image=file://"+tarballPath, "--json", "--no-verification", "--detector-timeout=30s", "--no-update")
	}

	// Capture output
	output, err := cmd.Output()
	if err != nil {
		// Check if it's an exit error (which is normal for trufflehog when no secrets found)
		if exitErr, ok := err.(*exec.ExitError); ok {
			// TruffleHog exits with code 183 when secrets are found, 0 when no secrets found
			if exitErr.ExitCode() == 0 {
				// No secrets found, which is not an error
				logger.L().Debug("trufflehog scan completed on tarball - no secrets found",
					helpers.String("tarballPath", tarballPath))
				return []TruffleHogResult{}, nil
			} else if exitErr.ExitCode() == 183 {
				// Secrets found, this is expected behavior
				logger.L().Debug("trufflehog scan completed on tarball - secrets found",
					helpers.String("tarballPath", tarballPath))
				// Continue to parse the output
			} else {
				// Other error
				return nil, fmt.Errorf("trufflehog command failed with exit code %d: %w", exitErr.ExitCode(), err)
			}
		} else {
			return nil, fmt.Errorf("trufflehog command failed on tarball: %w", err)
		}
	}

	// Parse the JSON output (trufflehog outputs one JSON object per line)
	results, err := t.parseTruffleHogOutput(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trufflehog output: %w", err)
	}

	// Note: Storage is handled by ScanImage method to use correct imageTag

	// Save to output file if specified
	if outputPath != "" {
		if err := t.saveResultsToFile(results, outputPath); err != nil {
			logger.L().Error("failed to save trufflehog results to file", helpers.Error(err))
		}
	}

	logger.L().Debug("trufflehog scan completed on tarball",
		helpers.String("tarballPath", tarballPath),
		helpers.Int("secretsFound", len(results)))

	return results, nil
}

// parseTruffleHogOutput parses the JSON output from trufflehog (one JSON object per line)
func (t *TruffleHogAdapter) parseTruffleHogOutput(output []byte) ([]TruffleHogResult, error) {
	var results []TruffleHogResult

	// Split output into lines and parse each line as a JSON object
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var result TruffleHogResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			logger.L().Warning("failed to parse trufflehog JSON line, skipping",
				helpers.Error(err),
				helpers.String("line", line))
			continue
		}

		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading trufflehog output: %w", err)
	}

	return results, nil
}

// saveResultsToFile saves the trufflehog results to a JSON file
func (t *TruffleHogAdapter) saveResultsToFile(results []TruffleHogResult, outputPath string) error {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal trufflehog results to JSON: %w", err)
	}

	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write trufflehog results to file: %w", err)
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
