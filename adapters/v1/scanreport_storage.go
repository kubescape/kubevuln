package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ScanReportStorageAdapter handles saving both dive and trufflehog reports to Kubernetes CRDs
type ScanReportStorageAdapter struct {
	namespace string
	client    dynamic.Interface
	gvr       schema.GroupVersionResource
}

// NewScanReportStorageAdapter creates a new unified scan report storage adapter
func NewScanReportStorageAdapter(namespace string) *ScanReportStorageAdapter {
	adapter := &ScanReportStorageAdapter{
		namespace: namespace,
		gvr: schema.GroupVersionResource{
			Group:    "kubevuln.io",
			Version:  "v1",
			Resource: "scanreports",
		},
	}

	if err := adapter.initK8sClient(); err != nil {
		logger.L().Error("failed to initialize k8s client for scan report storage", helpers.Error(err))
		return adapter
	}

	logger.L().Info("scan report CRD storage enabled successfully")
	return adapter
}

// initK8sClient initializes the Kubernetes client
func (s *ScanReportStorageAdapter) initK8sClient() error {
	var config *rest.Config
	var err error

	// Try in-cluster config first
	if config, err = rest.InClusterConfig(); err != nil {
		// Fall back to kubeconfig
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
		}

		if config, err = clientcmd.BuildConfigFromFlags("", kubeconfig); err != nil {
			return fmt.Errorf("failed to get k8s config: %w", err)
		}
	}

	if s.client, err = dynamic.NewForConfig(config); err != nil {
		return fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return nil
}

// SaveScanReport saves both dive and trufflehog reports to a single CRD
func (s *ScanReportStorageAdapter) SaveScanReport(ctx context.Context, imageTag, imageName, jobID string, diveResult *DiveResult, truffleHogResults []TruffleHogResult, outputPath string) error {
	// Try to save to CRD first
	if err := s.saveScanReportToCRD(ctx, imageTag, imageName, jobID, diveResult, truffleHogResults, outputPath); err != nil {
		logger.L().Error("failed to save scan report to CRD, falling back to file storage", helpers.Error(err))
		// Fall back to file storage
		return s.saveScanReportToFile(diveResult, truffleHogResults, outputPath)
	}

	return nil
}

// saveScanReportToCRD saves the scan report to Kubernetes CRD
func (s *ScanReportStorageAdapter) saveScanReportToCRD(ctx context.Context, imageTag, imageName, jobID string, diveResult *DiveResult, truffleHogResults []TruffleHogResult, outputPath string) error {
	if s.client == nil {
		return fmt.Errorf("k8s client not initialized")
	}

	// Sanitize labels to be Kubernetes-compliant
	sanitizedImageName := sanitizeLabel(imageName)
	sanitizedJobID := sanitizeLabel(jobID)

	// Read raw JSON files and store them as complete JSON strings
	var diveReportJSON string
	var truffleHogReportJSON string

	// Read dive report JSON file if it exists
	// The outputPath for dive is like: /tmp/dive-results/hello-world-latest-nohash-20250625-115520-3b72804357eecf9b-dive.json
	// The outputPath for trufflehog is like: /tmp/trufflehog-results/hello-world-latest-nohash-20250625-115520-3b72804357eecf9b-trufflehog.json

	var divePath, truffleHogPath string

	// Determine if this is a dive or trufflehog call based on outputPath
	if strings.Contains(outputPath, "dive-results") {
		// This is a dive scan call
		divePath = outputPath
		// Construct trufflehog path by replacing dive-results with trufflehog-results and dive.json with trufflehog.json
		truffleHogPath = strings.Replace(strings.Replace(outputPath, "dive-results", "trufflehog-results", 1), "-dive.json", "-trufflehog.json", 1)
	} else if strings.Contains(outputPath, "trufflehog-results") {
		// This is a trufflehog scan call
		truffleHogPath = outputPath
		// Construct dive path by replacing trufflehog-results with dive-results and trufflehog.json with dive.json
		divePath = strings.Replace(strings.Replace(outputPath, "trufflehog-results", "dive-results", 1), "-trufflehog.json", "-dive.json", 1)
	} else {
		// Fallback: construct both paths
		baseName := filepath.Base(outputPath)
		divePath = filepath.Join("/tmp/dive-results", baseName+"-dive.json")
		truffleHogPath = filepath.Join("/tmp/trufflehog-results", baseName+"-trufflehog.json")
	}

	// Read complete dive report as JSON string
	if diveData, err := os.ReadFile(divePath); err == nil {
		diveReportJSON = string(diveData) // Store complete JSON as string - exact same content as local file
		logger.L().Debug("read complete dive report JSON file", helpers.String("path", divePath), helpers.Int("size", len(diveData)))

		// Create separate CRD for dive report
		if err := s.createDiveCRD(ctx, imageTag, sanitizedImageName, sanitizedJobID, diveReportJSON, divePath); err != nil {
			logger.L().Error("failed to create dive CRD", helpers.Error(err))
		}
	} else {
		logger.L().Warning("failed to read dive report JSON file", helpers.Error(err), helpers.String("path", divePath))
	}

	// Read complete trufflehog report as JSON string
	if truffleHogData, err := os.ReadFile(truffleHogPath); err == nil {
		truffleHogReportJSON = string(truffleHogData) // Store complete JSON as string - exact same content as local file
		logger.L().Debug("read complete trufflehog report JSON file", helpers.String("path", truffleHogPath), helpers.Int("size", len(truffleHogData)))

		// Create separate CRD for trufflehog report
		if err := s.createTrufflehogCRD(ctx, imageTag, sanitizedImageName, sanitizedJobID, truffleHogReportJSON, truffleHogPath); err != nil {
			logger.L().Error("failed to create trufflehog CRD", helpers.Error(err))
		}
	} else {
		logger.L().Warning("failed to read trufflehog report JSON file", helpers.Error(err), helpers.String("path", truffleHogPath))
	}

	return nil
}

// createDiveCRD creates a separate CRD for dive report
func (s *ScanReportStorageAdapter) createDiveCRD(ctx context.Context, imageTag, sanitizedImageName, sanitizedJobID, diveReportJSON, divePath string) error {
	// Create the dive scan report object
	diveScanReport := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubevuln.io/v1",
			"kind":       "ScanReport",
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("%s-%s-dive", sanitizedImageName, sanitizedJobID), // Only dive in the name
				"namespace": s.namespace,
				"labels": map[string]interface{}{
					"image":      sanitizedImageName,
					"jobId":      sanitizedJobID,
					"dive":       "true", // Indicates this report contains dive analysis
					"reportType": "dive", // Indicates this is a dive report
					"tool":       "dive", // Tool identifier
				},
				"annotations": map[string]interface{}{
					"kubevuln.io/dive-report": "Complete dive analysis JSON report",
					"kubevuln.io/scan-tool":   "dive",
				},
			},
			"spec": map[string]interface{}{
				"image":       imageTag,
				"namespace":   s.namespace,
				"timestamp":   metav1.Now().Format("2006-01-02T15:04:05Z"),
				"clusterName": "default", // You can make this configurable
				"jobID":       sanitizedJobID,
				"diveReport":  diveReportJSON, // Complete dive JSON report
				"reportPath":  divePath,
			},
			"status": map[string]interface{}{
				"status":      "completed",
				"lastUpdated": metav1.Now().Format("2006-01-02T15:04:05Z"),
			},
		},
	}

	// Create the dive CRD resource
	_, err := s.client.Resource(s.gvr).Namespace(s.namespace).Create(ctx, diveScanReport, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create dive scan report CRD: %w", err)
	}

	logger.L().Info("dive scan report saved to CRD successfully",
		helpers.String("image", imageTag),
		helpers.String("namespace", s.namespace),
		helpers.String("jobID", sanitizedJobID),
		helpers.Int("diveReportSize", len(diveReportJSON)))

	return nil
}

// createTrufflehogCRD creates a separate CRD for trufflehog report
func (s *ScanReportStorageAdapter) createTrufflehogCRD(ctx context.Context, imageTag, sanitizedImageName, sanitizedJobID, truffleHogReportJSON, truffleHogPath string) error {
	// Create the trufflehog scan report object
	trufflehogScanReport := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubevuln.io/v1",
			"kind":       "ScanReport",
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("%s-%s-trufflehog", sanitizedImageName, sanitizedJobID), // Only trufflehog in the name
				"namespace": s.namespace,
				"labels": map[string]interface{}{
					"image":      sanitizedImageName,
					"jobId":      sanitizedJobID,
					"trufflehog": "true",       // Indicates this report contains trufflehog analysis
					"reportType": "trufflehog", // Indicates this is a trufflehog report
					"tool":       "trufflehog", // Tool identifier
				},
				"annotations": map[string]interface{}{
					"kubevuln.io/trufflehog-report": "Complete trufflehog secrets scan JSON report",
					"kubevuln.io/scan-tool":         "trufflehog",
				},
			},
			"spec": map[string]interface{}{
				"image":            imageTag,
				"namespace":        s.namespace,
				"timestamp":        metav1.Now().Format("2006-01-02T15:04:05Z"),
				"clusterName":      "default", // You can make this configurable
				"jobID":            sanitizedJobID,
				"trufflehogReport": truffleHogReportJSON, // Complete trufflehog JSON report
				"reportPath":       truffleHogPath,
			},
			"status": map[string]interface{}{
				"status":      "completed",
				"lastUpdated": metav1.Now().Format("2006-01-02T15:04:05Z"),
			},
		},
	}

	// Create the trufflehog CRD resource
	_, err := s.client.Resource(s.gvr).Namespace(s.namespace).Create(ctx, trufflehogScanReport, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create trufflehog scan report CRD: %w", err)
	}

	logger.L().Info("trufflehog scan report saved to CRD successfully",
		helpers.String("image", imageTag),
		helpers.String("namespace", s.namespace),
		helpers.String("jobID", sanitizedJobID),
		helpers.Int("trufflehogReportSize", len(truffleHogReportJSON)))

	return nil
}

// sanitizeLabel converts a string to a Kubernetes-compliant label value
func sanitizeLabel(value string) string {
	// Replace invalid characters with hyphens
	invalidChars := []string{"/", ":", "@", "=", "+", "&", "?", "#", "%", "!", "*", "(", ")", "[", "]", "{", "}", "|", "\\", "\"", "'", ";", ",", "<", ">", " "}
	result := value

	for _, char := range invalidChars {
		result = strings.ReplaceAll(result, char, "-")
	}

	// Remove consecutive hyphens
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}

	// Remove leading and trailing hyphens
	result = strings.Trim(result, "-")

	// Ensure it starts and ends with alphanumeric
	if len(result) > 0 {
		if !isAlphanumeric(rune(result[0])) {
			result = "a" + result
		}
		if len(result) > 0 && !isAlphanumeric(rune(result[len(result)-1])) {
			result = result + "a"
		}
	}

	// Limit length to 63 characters (Kubernetes label limit)
	if len(result) > 63 {
		result = result[:63]
		// Ensure it ends with alphanumeric
		if !isAlphanumeric(rune(result[len(result)-1])) {
			result = result[:len(result)-1] + "a"
		}
	}

	// If empty after sanitization, use a default value
	if result == "" {
		result = "default"
	}

	return result
}

// isAlphanumeric checks if a rune is alphanumeric
func isAlphanumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// saveScanReportToFile saves the scan report to local files as fallback
func (s *ScanReportStorageAdapter) saveScanReportToFile(diveResult *DiveResult, truffleHogResults []TruffleHogResult, outputPath string) error {
	// Save dive report
	if diveResult != nil {
		divePath := outputPath + "-dive.json"
		if err := s.saveDiveReportToFile(diveResult, divePath); err != nil {
			logger.L().Error("failed to save dive report to file", helpers.Error(err))
		}
	}

	// Save trufflehog report
	if len(truffleHogResults) > 0 {
		truffleHogPath := outputPath + "-trufflehog.json"
		if err := s.saveTruffleHogReportToFile(truffleHogResults, truffleHogPath); err != nil {
			logger.L().Error("failed to save trufflehog report to file", helpers.Error(err))
		}
	}

	return nil
}

// saveDiveReportToFile saves dive report to a JSON file
func (s *ScanReportStorageAdapter) saveDiveReportToFile(diveResult *DiveResult, outputPath string) error {
	data, err := json.MarshalIndent(diveResult, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal dive result: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write dive report to file: %w", err)
	}

	logger.L().Info("dive report saved to file", helpers.String("path", outputPath))
	return nil
}

// saveTruffleHogReportToFile saves trufflehog report to a JSON file
func (s *ScanReportStorageAdapter) saveTruffleHogReportToFile(truffleHogResults []TruffleHogResult, outputPath string) error {
	data, err := json.MarshalIndent(truffleHogResults, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal trufflehog results: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write trufflehog report to file: %w", err)
	}

	logger.L().Info("trufflehog report saved to file", helpers.String("path", outputPath))
	return nil
}
