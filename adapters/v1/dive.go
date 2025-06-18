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
	"go.opentelemetry.io/otel"
)

// DiveAdapter implements image layer scanning using dive as a subprocess
type DiveAdapter struct {
	divePath    string
	scanTimeout time.Duration
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
func NewDiveAdapter(divePath string, scanTimeout time.Duration) *DiveAdapter {
	if divePath == "" {
		divePath = "./dive" // Default to local dive binary
	}
	return &DiveAdapter{
		divePath:    divePath,
		scanTimeout: scanTimeout,
	}
}

// ScanImage runs dive as a subprocess to analyze the given image and saves the result as JSON
func (d *DiveAdapter) ScanImage(ctx context.Context, imageTag, outputPath string) (*DiveResult, error) {
	ctx, span := otel.Tracer("").Start(ctx, "DiveAdapter.ScanImage")
	defer span.End()

	logger.L().Debug("starting dive scan",
		helpers.String("imageTag", imageTag),
		helpers.String("outputPath", outputPath))

	// Create output directory if it doesn't exist
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Prepare dive command with JSON output
	cmd := exec.CommandContext(ctx, d.divePath, imageTag, "--json", outputPath)

	// Set timeout
	if d.scanTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.scanTimeout)
		defer cancel()
		cmd = exec.CommandContext(ctx, d.divePath, imageTag, "--json", outputPath)
	}

	// Run dive command
	logger.L().Debug("executing dive command",
		helpers.String("command", cmd.String()))

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("dive command failed: %w", err)
	}

	// Read and parse the JSON output
	result, err := d.readDiveResult(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read dive result: %w", err)
	}

	logger.L().Debug("dive scan completed",
		helpers.String("imageTag", imageTag),
		helpers.Int("layers", len(result.Layer)),
		helpers.Int("totalSize", int(result.Image.SizeBytes)))

	return result, nil
}

// readDiveResult reads and parses the JSON output file from dive
func (d *DiveAdapter) readDiveResult(outputPath string) (*DiveResult, error) {
	data, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read output file: %w", err)
	}

	var result DiveResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse dive JSON output: %w", err)
	}

	return &result, nil
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
