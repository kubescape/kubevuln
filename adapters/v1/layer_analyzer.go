package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/anchore/syft/syft/source"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"go.opentelemetry.io/otel"
)

// LayerAnalyzerResult represents analysis results for individual layers
type LayerAnalyzerResult struct {
	ImageName    string                 `json:"imageName"`
	TotalLayers  int                    `json:"totalLayers"`
	TotalSize    int64                  `json:"totalSize"`
	Layers       []LayerInfo            `json:"layers"`
	Efficiency   LayerEfficiencyMetrics `json:"efficiency"`
	AnalysisTime time.Time              `json:"analysisTime"`
}

// LayerInfo represents information about a single layer
type LayerInfo struct {
	Index       int    `json:"index"`
	Digest      string `json:"digest"`
	SizeBytes   int64  `json:"sizeBytes"`
	Command     string `json:"command"`
	FileCount   int    `json:"fileCount"`
	IsEfficient bool   `json:"isEfficient"`
}

// LayerEfficiencyMetrics represents efficiency analysis
type LayerEfficiencyMetrics struct {
	TotalSizeBytes          int64    `json:"totalSizeBytes"`
	InefficientBytes        int64    `json:"inefficientBytes"`
	EfficiencyScore         float64  `json:"efficiencyScore"`
	RedundantFiles          int      `json:"redundantFiles"`
	LargeFiles              int      `json:"largeFiles"`
	OptimizationSuggestions []string `json:"optimizationSuggestions"`
}

// LayerAnalyzer implements direct layer analysis without Docker archive reconstruction
type LayerAnalyzer struct {
	scanTimeout time.Duration
	storage     *ScanReportStorageAdapter
}

// NewLayerAnalyzer creates a new LayerAnalyzer instance
func NewLayerAnalyzer(scanTimeout time.Duration, storage *ScanReportStorageAdapter) *LayerAnalyzer {
	return &LayerAnalyzer{
		scanTimeout: scanTimeout,
		storage:     storage,
	}
}

// AnalyzeLayersFromStereoscope analyzes individual layers from Stereoscope's temp directory
func (la *LayerAnalyzer) AnalyzeLayersFromStereoscope(ctx context.Context, src source.Source, imageTag, imageName, jobID, outputPath string) (*LayerAnalyzerResult, error) {
	ctx, span := otel.Tracer("").Start(ctx, "LayerAnalyzer.AnalyzeLayersFromStereoscope")
	defer span.End()

	logger.L().Debug("starting layer analysis from Stereoscope",
		helpers.String("imageTag", imageTag),
		helpers.String("imageName", imageName),
		helpers.String("jobID", jobID))

	// Extract image metadata
	metadata, err := la.extractImageMetadata(src)
	if err != nil {
		return nil, fmt.Errorf("failed to extract image metadata: %w", err)
	}

	// Find Stereoscope temp directory
	stereoscopeTempDir, err := la.findStereoscopeTempDir()
	if err != nil {
		return nil, fmt.Errorf("failed to find Stereoscope temp directory: %w", err)
	}

	// Analyze each layer
	layers := make([]LayerInfo, 0, len(metadata.Layers))
	var totalSize int64
	var inefficientBytes int64

	for i, layer := range metadata.Layers {
		layerInfo, err := la.analyzeLayer(stereoscopeTempDir, i, layer)
		if err != nil {
			logger.L().Warning("failed to analyze layer, skipping",
				helpers.Error(err),
				helpers.Int("layerIndex", i),
				helpers.String("layerDigest", layer.Digest))
			continue
		}

		layers = append(layers, layerInfo)
		totalSize += layerInfo.SizeBytes

		// Simple efficiency heuristic: layers with many files or large size might be inefficient
		if layerInfo.FileCount > 1000 || layerInfo.SizeBytes > 50*1024*1024 { // 50MB
			layerInfo.IsEfficient = false
			inefficientBytes += layerInfo.SizeBytes
		} else {
			layerInfo.IsEfficient = true
		}
	}

	// Calculate efficiency metrics
	efficiencyScore := 1.0
	if totalSize > 0 {
		efficiencyScore = float64(totalSize-inefficientBytes) / float64(totalSize)
	}

	efficiency := LayerEfficiencyMetrics{
		TotalSizeBytes:          totalSize,
		InefficientBytes:        inefficientBytes,
		EfficiencyScore:         efficiencyScore,
		OptimizationSuggestions: la.generateOptimizationSuggestions(layers),
	}

	result := &LayerAnalyzerResult{
		ImageName:    imageName,
		TotalLayers:  len(layers),
		TotalSize:    totalSize,
		Layers:       layers,
		Efficiency:   efficiency,
		AnalysisTime: time.Now(),
	}

	// Save results
	if la.storage != nil {
		// Commented out: SaveScanReport expects *DiveResult, not *LayerAnalyzerResult
		// if err := la.storage.SaveScanReport(ctx, imageTag, imageName, jobID, result, nil, outputPath); err != nil {
		// 	logger.L().Error("failed to save layer analysis report to storage", helpers.Error(err))
		// }
	}

	// Save to file if outputPath is provided
	if outputPath != "" {
		if err := la.saveResultsToFile(result, outputPath); err != nil {
			logger.L().Error("failed to save layer analysis results to file", helpers.Error(err))
		}
	}

	logger.L().Debug("layer analysis completed",
		helpers.String("imageTag", imageTag),
		helpers.Int("layers", len(layers)),
		helpers.Int("totalSize", int(totalSize)),
		helpers.String("efficiencyScore", fmt.Sprintf("%.2f", efficiencyScore)))

	return result, nil
}

// extractImageMetadata extracts metadata from the source
func (la *LayerAnalyzer) extractImageMetadata(src source.Source) (*source.ImageMetadata, error) {
	desc := src.Describe()
	imgMetadata, ok := desc.Metadata.(*source.ImageMetadata)
	if !ok || imgMetadata == nil {
		return nil, fmt.Errorf("could not extract image metadata from source: %T", desc.Metadata)
	}
	if imgMetadata.Layers != nil && len(imgMetadata.Layers) > 0 {
		return imgMetadata, nil
	}
	return parseLayersFromConfigAndManifest(imgMetadata)
}

// findStereoscopeTempDir finds the Stereoscope temporary directory
func (la *LayerAnalyzer) findStereoscopeTempDir() (string, error) {
	stereoscopeTempDirs, err := filepath.Glob(filepath.Join(os.TempDir(), "stereoscope-*"))
	if err != nil {
		return "", fmt.Errorf("failed to find stereoscope temp directories: %w", err)
	}

	if len(stereoscopeTempDirs) == 0 {
		return "", fmt.Errorf("no stereoscope temp directories found")
	}

	// Use the most recent directory
	return stereoscopeTempDirs[len(stereoscopeTempDirs)-1], nil
}

// analyzeLayer analyzes a single layer
func (la *LayerAnalyzer) analyzeLayer(stereoscopeTempDir string, layerIndex int, layer source.LayerMetadata) (LayerInfo, error) {
	layerInfo := LayerInfo{
		Index:  layerIndex,
		Digest: layer.Digest,
	}

	// Try to find the layer file
	layerFileName := fmt.Sprintf("%s.tar", layer.Digest)
	layerPath := filepath.Join(stereoscopeTempDir, layerFileName)

	if _, err := os.Stat(layerPath); os.IsNotExist(err) {
		// Try alternative naming patterns
		layerPath = filepath.Join(stereoscopeTempDir, fmt.Sprintf("layer_%d.tar", layerIndex))
		if _, err := os.Stat(layerPath); os.IsNotExist(err) {
			return layerInfo, fmt.Errorf("layer file not found: %s", layerFileName)
		}
	}

	// Analyze the layer file
	fileInfo, err := os.Stat(layerPath)
	if err != nil {
		return layerInfo, fmt.Errorf("failed to stat layer file: %w", err)
	}

	layerInfo.SizeBytes = fileInfo.Size()

	// Simple file count estimation (this is a rough estimate)
	layerInfo.FileCount = int(layerInfo.SizeBytes / 1024) // Rough estimate: 1KB per file

	// Note: source.LayerMetadata doesn't have CreatedBy field, so we skip it
	// layerInfo.Command will remain empty

	return layerInfo, nil
}

// generateOptimizationSuggestions generates optimization suggestions based on layer analysis
func (la *LayerAnalyzer) generateOptimizationSuggestions(layers []LayerInfo) []string {
	var suggestions []string

	var largeLayers int
	var redundantLayers int

	for _, layer := range layers {
		if layer.SizeBytes > 100*1024*1024 { // 100MB
			largeLayers++
		}
		if layer.FileCount > 5000 {
			redundantLayers++
		}
	}

	if largeLayers > 0 {
		suggestions = append(suggestions, fmt.Sprintf("Consider combining %d large layers to reduce image size", largeLayers))
	}

	if redundantLayers > 0 {
		suggestions = append(suggestions, fmt.Sprintf("Consider optimizing %d layers with many files", redundantLayers))
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions, "Image appears to be well-optimized")
	}

	return suggestions
}

// saveResultsToFile saves the analysis results to a JSON file
func (la *LayerAnalyzer) saveResultsToFile(result *LayerAnalyzerResult, outputPath string) error {
	// Create output directory if it doesn't exist
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results to JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write results to file: %w", err)
	}

	return nil
}

// Version returns the layer analyzer version
func (la *LayerAnalyzer) Version() string {
	return "1.0.0"
}
