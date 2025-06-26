package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"go.opentelemetry.io/otel"
)

// DiveAdapter implements image layer scanning using dive as a subprocess
type DiveAdapter struct {
	divePath        string
	scanTimeout     time.Duration
	storage         *ScanReportStorageAdapter
	imageDownloader *ImageDownloader
}

// DiveResult represents the JSON output from dive
type DiveResult struct {
	Image struct {
		SizeBytes        int64   `json:"sizeBytes"`
		InefficientBytes int64   `json:"inefficientBytes"`
		EfficiencyScore  float64 `json:"efficiencyScore"`
		FileReference    []struct {
			Count     int    `json:"count"`
			SizeBytes int64  `json:"sizeBytes"`
			File      string `json:"file"`
		} `json:"fileReference"`
	} `json:"image"`
	Layer []struct {
		Index     int    `json:"index"`
		ID        string `json:"id"`
		DigestId  string `json:"digestId"`
		SizeBytes int64  `json:"sizeBytes"`
		Command   string `json:"command"`
		FileList  []struct {
			Path     string `json:"path"`
			TypeFlag int    `json:"typeFlag"`
			LinkName string `json:"linkName"`
			Size     int64  `json:"size"`
			FileMode int    `json:"fileMode"`
			UID      int    `json:"uid"`
			GID      int    `json:"gid"`
			IsDir    bool   `json:"isDir"`
		} `json:"fileList"`
	} `json:"layer"`
}

// NewDiveAdapter initializes the DiveAdapter struct
func NewDiveAdapter(divePath string, scanTimeout time.Duration, storage *ScanReportStorageAdapter) *DiveAdapter {
	if divePath == "" {
		divePath = "./dive" // Default to local dive binary
	}
	return &DiveAdapter{
		divePath:        divePath,
		scanTimeout:     scanTimeout,
		storage:         storage,
		imageDownloader: NewImageDownloader(1024*1024*1024*2, scanTimeout), // 2GB max image size
	}
}

// ScanImage downloads an image and runs dive analysis on it
func (d *DiveAdapter) ScanImage(ctx context.Context, imageID, imageTag string, registryOptions domain.RegistryOptions, imageName, jobID, outputPath string) (*DiveResult, error) {
	ctx, span := otel.Tracer("").Start(ctx, "DiveAdapter.ScanImage")
	defer span.End()

	logger.L().Debug("starting dive scan with image download",
		helpers.String("imageID", imageID),
		helpers.String("imageTag", imageTag),
		helpers.String("imageName", imageName),
		helpers.String("jobID", jobID))

	// Download the image as a tarball first
	downloadResult, err := d.imageDownloader.DownloadImageAsTarball(ctx, imageID, imageTag, registryOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to download image for dive scan: %w", err)
	}
	defer downloadResult.Cleanup()

	logger.L().Debug("image downloaded for dive scan",
		helpers.String("tarballPath", downloadResult.TarballPath),
		helpers.Int("imageSize", int(downloadResult.ImageSize)))

	// Now run dive scan on the downloaded tarball
	result, err := d.ScanTarball(ctx, downloadResult.TarballPath, imageName, jobID, outputPath)
	if err != nil {
		return nil, err
	}

	// Save to unified storage with correct imageTag (CRD or file)
	if d.storage != nil {
		if err := d.storage.SaveScanReport(ctx, imageTag, imageName, jobID, result, nil, outputPath); err != nil {
			logger.L().Error("failed to save dive report to storage with correct imageTag", helpers.Error(err))
		}
	}

	return result, nil
}

// ScanTarball runs dive as a subprocess to analyze the given tarball and saves the result
func (d *DiveAdapter) ScanTarball(ctx context.Context, tarballPath, imageName, jobID, outputPath string) (*DiveResult, error) {
	ctx, span := otel.Tracer("").Start(ctx, "DiveAdapter.ScanTarball")
	defer span.End()

	logger.L().Debug("starting dive scan on tarball",
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

	// Prepare dive command with JSON output to stdout for tarball
	// Use --source docker-archive for tarball files
	// Create a temporary output file for dive
	tempOutputFile := tarballPath + ".dive-output.json"
	defer os.Remove(tempOutputFile) // Clean up temp file

	cmd := exec.CommandContext(ctx, d.divePath, "--source", "docker-archive", tarballPath, "--json", tempOutputFile)

	// Set timeout
	if d.scanTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.scanTimeout)
		defer cancel()
		cmd = exec.CommandContext(ctx, d.divePath, "--source", "docker-archive", tarballPath, "--json", tempOutputFile)
	}

	// Run dive command
	logger.L().Debug("executing dive command on tarball",
		helpers.String("command", cmd.String()))

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("dive command failed on tarball: %w", err)
	}

	// Read the JSON output from the temporary file
	jsonOutput, err := os.ReadFile(tempOutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read dive output file: %w", err)
	}

	// Parse the JSON output directly
	result, err := d.parseDiveResult(jsonOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dive result: %w", err)
	}

	// Note: Storage is handled by ScanImage method to use correct imageTag

	// Save to output file if specified
	if outputPath != "" {
		if err := d.saveResultToFile(result, outputPath); err != nil {
			logger.L().Error("failed to save dive result to file", helpers.Error(err))
		}
	}

	logger.L().Debug("dive scan completed on tarball",
		helpers.String("tarballPath", tarballPath),
		helpers.Int("layers", len(result.Layer)),
		helpers.Int("totalSize", int(result.Image.SizeBytes)))

	return result, nil
}

// parseDiveResult parses the JSON output directly from dive command
func (d *DiveAdapter) parseDiveResult(output []byte) (*DiveResult, error) {
	var result DiveResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse dive JSON output: %w", err)
	}

	return &result, nil
}

// saveResultToFile saves the dive result to a JSON file
func (d *DiveAdapter) saveResultToFile(result *DiveResult, outputPath string) error {
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal dive result to JSON: %w", err)
	}

	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write dive result to file: %w", err)
	}

	return nil
}

// Version returns the dive version
func (d *DiveAdapter) Version() string {
	cmd := exec.Command(d.divePath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return string(output)
}
