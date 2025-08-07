package v1

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/DmitriyVTitov/size"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	sbomcataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/eapache/go-resiliency/deadline"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/internal/tools"
	"go.opentelemetry.io/otel"
)

// SyftAdapter implements SBOMCreator from ports using Syft's API
type SyftAdapter struct {
	maxImageSize      int64
	maxSBOMSize       int
	pullMutex         sync.Mutex
	scanTimeout       time.Duration
	scanEmbeddedSBOMs bool
	diveAdapter       *DiveAdapter
	truffleHogAdapter *TruffleHogAdapter
	storage           *ScanReportStorageAdapter
}

const digestDelim = "@"

var _ ports.SBOMCreator = (*SyftAdapter)(nil)

// NewSyftAdapter initializes the SyftAdapter struct
func NewSyftAdapter(scanTimeout time.Duration, maxImageSize int64, maxSBOMSize int, scanEmbeddedSBOMs bool, storage *ScanReportStorageAdapter) *SyftAdapter {
	return &SyftAdapter{
		maxImageSize:      maxImageSize,
		maxSBOMSize:       maxSBOMSize,
		scanTimeout:       scanTimeout,
		scanEmbeddedSBOMs: scanEmbeddedSBOMs,
		storage:           storage,
		diveAdapter:       NewDiveAdapter("/usr/bin/dive", scanTimeout, storage),
		truffleHogAdapter: NewTruffleHogAdapter("/usr/bin/trufflehog", scanTimeout, storage),
	}
}

// NormalizeImageID normalizes the image ID by removing the digest if present
func NormalizeImageID(imageID, imageTag string) string {
	if imageTag != "" {
		// If we have an image tag, use it as the base
		if strings.Contains(imageTag, digestDelim) {
			// Remove digest from image tag
			parts := strings.Split(imageTag, digestDelim)
			return parts[0]
		}
		return imageTag
	}

	// If we only have imageID, remove digest if present
	if strings.Contains(imageID, digestDelim) {
		parts := strings.Split(imageID, digestDelim)
		return parts[0]
	}

	return imageID
}

func (s *SyftAdapter) CreateSBOM(ctx context.Context, name, imageID, imageTag string, options domain.RegistryOptions) (domain.SBOM, error) {
	ctx, span := otel.Tracer("").Start(ctx, "SyftAdapter.CreateSBOM")
	defer span.End()

	if imageTag != "" {
		imageID = NormalizeImageID(imageID, imageTag)
	}
	// prepare an SBOM and fill it progressively
	domainSBOM := domain.SBOM{
		Name:               name,
		SBOMCreatorVersion: s.Version(),
		SBOMCreatorName:    "syft",
		Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey:     imageID,
			helpersv1.ToolVersionMetadataKey: s.Version(),
		},
		Labels: tools.LabelsFromImageID(imageID),
	}
	domainSBOM.Annotations[helpersv1.ImageTagMetadataKey] = imageTag

	// translate business models into Syft models
	// Note: Not setting default platform to allow multi-platform image selection
	credentials := make([]image.RegistryCredentials, len(options.Credentials))
	for i, v := range options.Credentials {
		credentials[i] = image.RegistryCredentials{
			Authority: v.Authority,
			Username:  v.Username,
			Password:  v.Password,
			Token:     v.Token,
		}
	}
	registryOptions := image.RegistryOptions{
		InsecureSkipTLSVerify: options.InsecureSkipTLSVerify,
		InsecureUseHTTP:       options.InsecureUseHTTP,
		Credentials:           credentials,
	}

	// prepare temporary directory for image download
	t := file.NewTempDirGenerator("stereoscope")

	// download image
	logger.L().Debug("downloading image", helpers.String("imageID", imageID))

	ctxWithSize := context.WithValue(context.Background(), image.MaxImageSize, s.maxImageSize)
	src, err := syft.GetSource(ctxWithSize, imageID, syft.DefaultGetSourceConfig().WithRegistryOptions(&registryOptions).WithSources("registry"))

	if err != nil && strings.Contains(err.Error(), "MANIFEST_UNKNOWN") {
		logger.L().Debug("got MANIFEST_UNKNOWN, retrying with imageTag",
			helpers.String("imageTag", imageTag),
			helpers.String("imageID", imageID))
		src, err = syft.GetSource(ctxWithSize, imageTag, syft.DefaultGetSourceConfig().WithRegistryOptions(&registryOptions).WithSources("registry"))
	}

	if err != nil && strings.Contains(err.Error(), "401 Unauthorized") {
		logger.L().Debug("got 401, retrying without credentials",
			helpers.String("imageID", imageID))
		registryOptions.Credentials = nil
		src, err = syft.GetSource(ctxWithSize, imageID, syft.DefaultGetSourceConfig().WithRegistryOptions(&registryOptions).WithSources("registry"))
	}

	switch {
	case err != nil && strings.Contains(err.Error(), image.ErrImageTooLarge.Error()):
		logger.L().Ctx(ctx).Warning("Image exceeds size limit",
			helpers.Int("maxImageSize", int(s.maxImageSize)),
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.Incomplete
		return domainSBOM, nil
	case err != nil && strings.Contains(err.Error(), "401 Unauthorized"):
		domainSBOM.Status = helpersv1.Unauthorize
		return domainSBOM, err
	case err != nil:
		return domainSBOM, err
	}

	// generate SBOM
	// use a deadline to prevent the process from hanging for too long
	// TODO check memory usage and see if we can kill the goroutine
	var syftSBOM *sbom.SBOM
	// ensure no parallel pulls
	s.pullMutex.Lock()
	defer s.pullMutex.Unlock()
	dl := deadline.New(s.scanTimeout)
	err = dl.Run(func(stopper <-chan struct{}) error {
		// generate SBOM
		logger.L().Debug("generating SBOM",
			helpers.String("imageID", imageID))
		cfg := syft.DefaultCreateSBOMConfig()
		cfg.ToolName = name
		cfg.ToolVersion = s.Version()
		if s.scanEmbeddedSBOMs {
			// ask Syft to also scan the image for embedded SBOMs
			cfg.WithCatalogers(pkgcataloging.NewCatalogerReference(sbomcataloger.NewCataloger(), []string{pkgcataloging.ImageTag}))
		}
		syftSBOM, err = syft.CreateSBOM(ctx, src, cfg)
		if err != nil {
			return fmt.Errorf("failed to generate SBOM: %w", err)
		}

		// Note: Tarball creation is now handled by ImageDownloader in dive/trufflehog scans
		// This eliminates the minimal tarball issue and provides proper image content

		return nil
	})
	switch {
	case errors.Is(err, deadline.ErrTimedOut):
		logger.L().Ctx(ctx).Warning("Syft timed out",
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.Incomplete
		return domainSBOM, nil
	case err == nil:
		// continue
	default:
		// also mark as incomplete if we failed to extract packages
		domainSBOM.Status = helpersv1.Incomplete
		return domainSBOM, err
	}

	// check the size of the SBOM
	sz := size.Of(syftSBOM)
	domainSBOM.Annotations[helpersv1.ResourceSizeMetadataKey] = fmt.Sprintf("%d", sz)
	if sz > s.maxSBOMSize {
		logger.L().Ctx(ctx).Warning("SBOM exceeds size limit",
			helpers.Int("maxImageSize", s.maxSBOMSize),
			helpers.Int("size", sz),
			helpers.String("imageID", imageID))
		domainSBOM.Status = helpersv1.TooLarge
		return domainSBOM, nil
	}

	// mark SBOM as ready
	domainSBOM.Status = helpersv1.Ready

	// convert SBOM
	logger.L().Debug("converting SBOM",
		helpers.String("imageID", imageID))
	domainSBOM.Content, err = s.syftToDomain(*syftSBOM)
	if err != nil {
		return domainSBOM, err
	}

	// Run dive/trufflehog scans asynchronously using the ImageDownloader approach
	logger.L().Debug("starting dive and trufflehog scans with direct image download",
		helpers.String("imageID", imageID),
		helpers.String("imageTag", imageTag))

	// Run dive scan with direct image download
	go func() {
		diveCtx, cancel := context.WithTimeout(context.Background(), s.scanTimeout)
		defer cancel()
		timestamp := time.Now().Format("20060102-150405")
		jobID := generateJobID(imageTag, timestamp)
		outputPath := fmt.Sprintf("/tmp/dive-results/%s-%s-%s-dive.json", name, timestamp, jobID)

		logger.L().Debug("starting dive scan with image download",
			helpers.String("imageID", imageID),
			helpers.String("imageTag", imageTag),
			helpers.String("outputPath", outputPath),
			helpers.String("jobID", jobID))

		_, diveErr := s.diveAdapter.ScanImage(diveCtx, imageID, imageTag, options, name, jobID, outputPath)
		if diveErr != nil {
			logger.L().Ctx(ctx).Warning("dive scan failed",
				helpers.Error(diveErr),
				helpers.String("imageID", imageID))
		} else {
			logger.L().Debug("dive scan completed successfully",
				helpers.String("imageID", imageID),
				helpers.String("outputPath", outputPath))
		}
	}()

	// Run trufflehog scan with direct image download
	go func() {
		truffleHogCtx, cancel := context.WithTimeout(context.Background(), s.scanTimeout)
		defer cancel()
		timestamp := time.Now().Format("20060102-150405")
		jobID := generateJobID(imageTag, timestamp)
		outputPath := fmt.Sprintf("/tmp/trufflehog-results/%s-%s-%s-trufflehog.json", name, timestamp, jobID)

		logger.L().Debug("starting trufflehog scan with image download",
			helpers.String("imageID", imageID),
			helpers.String("imageTag", imageTag),
			helpers.String("outputPath", outputPath),
			helpers.String("jobID", jobID))

		_, truffleHogErr := s.truffleHogAdapter.ScanImage(truffleHogCtx, imageID, imageTag, options, name, jobID, outputPath)
		if truffleHogErr != nil {
			logger.L().Ctx(ctx).Warning("trufflehog scan failed",
				helpers.Error(truffleHogErr),
				helpers.String("imageID", imageID))
		} else {
			logger.L().Debug("trufflehog scan completed successfully",
				helpers.String("imageID", imageID),
				helpers.String("outputPath", outputPath))
		}
	}()

	// Clean up Stereoscope temp directory and close source AFTER all processing is complete
	defer func(t *file.TempDirGenerator) {
		err := t.Cleanup()
		if err != nil {
			logger.L().Ctx(ctx).Warning("failed to cleanup temp dir", helpers.Error(err),
				helpers.String("imageID", imageID))
		}
	}(t)

	defer func(src source.Source) {
		if err := src.Close(); err != nil {
			logger.L().Ctx(ctx).Warning("failed to close source", helpers.Error(err),
				helpers.String("imageID", imageID))
		}
	}(src)

	// return SBOM
	logger.L().Debug("returning SBOM",
		helpers.String("imageID", imageID),
		helpers.Int("packages", len(domainSBOM.Content.Artifacts)))
	return domainSBOM, nil
}

// Version returns Syft's version which is used to tag SBOMs
func (s *SyftAdapter) Version() string {
	v := tools.PackageVersion("github.com/anchore/syft")
	// no more processing needed
	return v
}

// generateJobID creates a unique job ID based on image tag and timestamp
func generateJobID(imageTag, timestamp string) string {
	// Create a hash from image tag and timestamp to ensure uniqueness
	hash := sha256.Sum256([]byte(imageTag + timestamp))
	return hex.EncodeToString(hash[:8]) // Use first 8 characters for readability
}

// saveImageAsDockerTarball exports the pulled image as a Docker tarball using docker save
func (s *SyftAdapter) saveImageAsDockerTarball(imageTag, tarPath string) error {
	if err := os.MkdirAll(filepath.Dir(tarPath), 0755); err != nil {
		return fmt.Errorf("failed to create tarball dir: %w", err)
	}

	// Use docker save to create the tarball
	cmd := exec.Command("docker", "save", "-o", tarPath, imageTag)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to save image as tarball: %w", err)
	}

	return nil
}

// createTarballFromStereoscope creates a Docker tarball from Stereoscope's downloaded image data
func (s *SyftAdapter) createTarballFromStereoscope(ctx context.Context, src source.Source, imageTag, name, stereoscopeTempDirPattern string) (string, error) {
	logger.L().Debug("creating tarball from Stereoscope image metadata",
		helpers.String("imageTag", imageTag))

	// Create temp directory for tarball
	tempDir, err := os.MkdirTemp("", "kubevuln-tarball-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Create tarball path
	tarballPath := filepath.Join(tempDir, fmt.Sprintf("%s.tar", strings.ReplaceAll(name, "/", "_")))

	// Try to extract image metadata from the source
	imageMetadata, err := s.extractImageMetadata(src)
	if err != nil {
		logger.L().Warning("failed to extract image metadata, creating minimal tarball",
			helpers.Error(err),
			helpers.String("imageTag", imageTag))
		return s.createMinimalDockerTarball(tarballPath)
	}

	// Create proper Docker archive with real metadata and layers
	err = s.createProperDockerTarball(tarballPath, imageMetadata, stereoscopeTempDirPattern)
	if err != nil {
		logger.L().Warning("failed to create proper Docker tarball, falling back to minimal",
			helpers.Error(err),
			helpers.String("imageTag", imageTag))
		return s.createMinimalDockerTarball(tarballPath)
	}

	logger.L().Debug("successfully created proper Docker tarball",
		helpers.String("tarballPath", tarballPath),
		helpers.String("imageTag", imageTag),
		helpers.Int("layers", len(imageMetadata.Layers)))

	return tarballPath, nil
}

// extractImageMetadata extracts metadata from the source
func (s *SyftAdapter) extractImageMetadata(src source.Source) (*source.ImageMetadata, error) {
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

// createProperDockerTarball creates a proper Docker archive with real metadata and layers
func (s *SyftAdapter) createProperDockerTarball(tarballPath string, metadata *source.ImageMetadata, stereoscopeTempDirPattern string) error {
	// Create the tarball file
	tarFile, err := os.Create(tarballPath)
	if err != nil {
		return fmt.Errorf("failed to create tarball file: %w", err)
	}
	defer tarFile.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(tarFile)
	defer tarWriter.Close()

	// Find Stereoscope temp directory
	stereoscopeTempDirs, err := filepath.Glob(stereoscopeTempDirPattern)
	if err != nil {
		return fmt.Errorf("failed to find stereoscope temp directories: %w", err)
	}

	if len(stereoscopeTempDirs) == 0 {
		return fmt.Errorf("no stereoscope temp directories found")
	}

	// Use the most recent directory
	latestDir := stereoscopeTempDirs[len(stereoscopeTempDirs)-1]

	// Create manifest.json with real layer information
	layerNames := make([]string, len(metadata.Layers))
	for i, layer := range metadata.Layers {
		layerNames[i] = fmt.Sprintf("%s.tar", layer.Digest)
	}

	manifest := map[string]interface{}{
		"Config":   "config.json",
		"RepoTags": []string{},
		"Layers":   layerNames,
	}
	manifestBytes, err := json.Marshal([]map[string]interface{}{manifest})
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	// Add manifest.json
	manifestEntry := &tar.Header{
		Name: "manifest.json",
		Mode: 0644,
		Size: int64(len(manifestBytes)),
	}
	if err := tarWriter.WriteHeader(manifestEntry); err != nil {
		return fmt.Errorf("failed to write manifest header: %w", err)
	}
	if _, err := tarWriter.Write(manifestBytes); err != nil {
		return fmt.Errorf("failed to write manifest content: %w", err)
	}

	// Add config.json (use the raw config from metadata)
	configEntry := &tar.Header{
		Name: "config.json",
		Mode: 0644,
		Size: int64(len(metadata.RawConfig)),
	}
	if err := tarWriter.WriteHeader(configEntry); err != nil {
		return fmt.Errorf("failed to write config header: %w", err)
	}
	if _, err := tarWriter.Write(metadata.RawConfig); err != nil {
		return fmt.Errorf("failed to write config content: %w", err)
	}

	// Add layer files
	for i, layer := range metadata.Layers {
		layerFileName := fmt.Sprintf("%s.tar", layer.Digest)

		// Look for the layer file in Stereoscope temp directory
		layerPath := filepath.Join(latestDir, layerFileName)
		if _, err := os.Stat(layerPath); os.IsNotExist(err) {
			// Try alternative naming patterns
			layerPath = filepath.Join(latestDir, fmt.Sprintf("layer_%d.tar", i))
			if _, err := os.Stat(layerPath); os.IsNotExist(err) {
				logger.L().Warning("layer file not found, skipping",
					helpers.String("layerDigest", layer.Digest),
					helpers.String("expectedPath", layerPath))
				continue
			}
		}

		// Read layer file
		layerData, err := os.ReadFile(layerPath)
		if err != nil {
			logger.L().Warning("failed to read layer file, skipping",
				helpers.Error(err),
				helpers.String("layerPath", layerPath))
			continue
		}

		// Add layer to tarball
		layerEntry := &tar.Header{
			Name: layerFileName,
			Mode: 0644,
			Size: int64(len(layerData)),
		}
		if err := tarWriter.WriteHeader(layerEntry); err != nil {
			return fmt.Errorf("failed to write layer header: %w", err)
		}
		if _, err := tarWriter.Write(layerData); err != nil {
			return fmt.Errorf("failed to write layer content: %w", err)
		}

		logger.L().Debug("added layer to tarball",
			helpers.String("layerName", layerFileName),
			helpers.Int("size", len(layerData)))
	}

	return nil
}

// createMinimalDockerTarball creates a minimal Docker tarball structure
func (s *SyftAdapter) createMinimalDockerTarball(tarballPath string) (string, error) {
	// Create the tarball file
	tarFile, err := os.Create(tarballPath)
	if err != nil {
		return "", fmt.Errorf("failed to create tarball file: %w", err)
	}
	defer tarFile.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(tarFile)
	defer tarWriter.Close()

	// Add a minimal manifest.json
	manifest := `[{"Config":"config.json","RepoTags":[],"Layers":[]}]`
	manifestEntry := &tar.Header{
		Name: "manifest.json",
		Mode: 0644,
		Size: int64(len(manifest)),
	}
	if err := tarWriter.WriteHeader(manifestEntry); err != nil {
		return "", fmt.Errorf("failed to write manifest header: %w", err)
	}
	if _, err := tarWriter.Write([]byte(manifest)); err != nil {
		return "", fmt.Errorf("failed to write manifest content: %w", err)
	}

	// Add a minimal config.json
	config := `{"architecture":"amd64","config":{},"container":"","container_config":{},"created":"2024-01-01T00:00:00Z","docker_version":"","history":[],"os":"linux","rootfs":{"diff_ids":[],"type":"layers"}}`
	configEntry := &tar.Header{
		Name: "config.json",
		Mode: 0644,
		Size: int64(len(config)),
	}
	if err := tarWriter.WriteHeader(configEntry); err != nil {
		return "", fmt.Errorf("failed to write config header: %w", err)
	}
	if _, err := tarWriter.Write([]byte(config)); err != nil {
		return "", fmt.Errorf("failed to write config content: %w", err)
	}

	return tarballPath, nil
}

// createEmptyTarball creates an empty tarball as a fallback
func (s *SyftAdapter) createEmptyTarball(tarballPath, tempDir string) (string, error) {
	// Create an empty tarball
	cmd := exec.Command("tar", "-cf", tarballPath, "--files-from", "/dev/null")

	// Set up pipes for error handling
	stderr, err := cmd.StderrPipe()
	if err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to start tar command: %w", err)
	}

	// Read stderr for any errors
	stderrOutput, _ := io.ReadAll(stderr)

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("tar command failed: %w, stderr: %s", err, string(stderrOutput))
	}

	return tarballPath, nil
}
