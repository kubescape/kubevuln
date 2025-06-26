package v1

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"go.opentelemetry.io/otel"
)

// ImageDownloader handles downloading container images and converting them to tarball format
type ImageDownloader struct {
	maxImageSize int64
	scanTimeout  time.Duration
}

// DownloadResult contains the result of an image download operation
type DownloadResult struct {
	TarballPath string
	ImageSize   int64
	TempDir     string // For cleanup
}

// NewImageDownloader creates a new ImageDownloader instance
func NewImageDownloader(maxImageSize int64, scanTimeout time.Duration) *ImageDownloader {
	return &ImageDownloader{
		maxImageSize: maxImageSize,
		scanTimeout:  scanTimeout,
	}
}

// DownloadImageAsTarball downloads a container image and converts it to a Docker tarball
// Uses the same authentication strategy as syft for consistency
func (id *ImageDownloader) DownloadImageAsTarball(ctx context.Context, imageID, imageTag string, options domain.RegistryOptions) (*DownloadResult, error) {
	ctx, span := otel.Tracer("").Start(ctx, "ImageDownloader.DownloadImageAsTarball")
	defer span.End()

	// Apply timeout to the context if configured
	if id.scanTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, id.scanTimeout)
		defer cancel()
	}

	logger.L().Debug("starting image download",
		helpers.String("imageID", imageID),
		helpers.String("imageTag", imageTag))

	// Normalize image ID similar to syft
	if imageTag != "" {
		imageID = NormalizeImageID(imageID, imageTag)
	}

	// Create temporary directory for the tarball
	tempDir, err := os.MkdirTemp("", "kubevuln-image-download-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Create tarball path
	sanitizedName := strings.ReplaceAll(strings.ReplaceAll(imageID, "/", "_"), ":", "_")
	tarballPath := filepath.Join(tempDir, fmt.Sprintf("%s.tar", sanitizedName))

	// Parse the image reference
	ref, err := name.ParseReference(imageID)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("failed to parse image reference %s: %w", imageID, err)
	}

	// Set up authentication options using the same strategy as syft
	authOptions := id.buildAuthOptions(ctx, options)

	// Download image using go-containerregistry with syft-like retry strategy
	logger.L().Debug("downloading image with go-containerregistry",
		helpers.String("reference", ref.String()))

	var img v1.Image
	var downloadErr error

	// First attempt: try with original imageID
	img, downloadErr = remote.Image(ref, authOptions...)

	// Retry strategy similar to syft
	if downloadErr != nil && strings.Contains(downloadErr.Error(), "MANIFEST_UNKNOWN") && imageTag != "" && imageTag != imageID {
		logger.L().Debug("got MANIFEST_UNKNOWN, retrying with imageTag",
			helpers.String("imageTag", imageTag),
			helpers.String("imageID", imageID))

		altRef, parseErr := name.ParseReference(imageTag)
		if parseErr == nil {
			img, downloadErr = remote.Image(altRef, authOptions...)
		}
	}

	// Retry without credentials on 401 (same as syft strategy)
	if downloadErr != nil && strings.Contains(downloadErr.Error(), "401 Unauthorized") {
		logger.L().Debug("got 401, retrying without credentials",
			helpers.String("imageID", imageID))

		// Build options without credentials (anonymous access)
		authOptionsNoAuth := id.buildAuthOptionsWithoutCredentials(ctx, options)
		img, downloadErr = remote.Image(ref, authOptionsNoAuth...)
	}

	if downloadErr != nil {
		// Clean up temp directory on error
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("failed to download image %s: %w", ref.String(), downloadErr)
	}

	// Check image size if limit is set
	if id.maxImageSize > 0 {
		manifest, err := img.Manifest()
		if err == nil {
			var totalSize int64
			for _, layer := range manifest.Layers {
				totalSize += layer.Size
			}
			if totalSize > id.maxImageSize {
				os.RemoveAll(tempDir)
				return nil, fmt.Errorf("image exceeds size limit (%d bytes): actual size %d bytes", id.maxImageSize, totalSize)
			}
		}
	}

	// Get image size for reporting
	var imageSize int64
	if manifest, err := img.Manifest(); err == nil {
		for _, layer := range manifest.Layers {
			imageSize += layer.Size
		}
	}

	logger.L().Debug("image downloaded successfully",
		helpers.String("reference", ref.String()),
		helpers.Int("size", int(imageSize)))

	// Save image as Docker tarball using go-containerregistry's tarball package
	logger.L().Debug("saving image as Docker tarball",
		helpers.String("tarballPath", tarballPath))

	err = tarball.WriteToFile(tarballPath, ref, img)
	if err != nil {
		// Clean up on error
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("failed to save image as tarball: %w", err)
	}

	// Verify tarball was created and has content
	if stat, err := os.Stat(tarballPath); err != nil {
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("tarball was not created: %w", err)
	} else if stat.Size() == 0 {
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("tarball is empty")
	} else {
		logger.L().Debug("image tarball created successfully",
			helpers.String("tarballPath", tarballPath),
			helpers.Int("tarballSize", int(stat.Size())))
	}

	return &DownloadResult{
		TarballPath: tarballPath,
		ImageSize:   imageSize,
		TempDir:     tempDir,
	}, nil
}

// Cleanup removes the temporary directory and tarball
func (dr *DownloadResult) Cleanup() error {
	if dr.TempDir != "" {
		return os.RemoveAll(dr.TempDir)
	}
	return nil
}

// insecureTransport is a simple http.RoundTripper that skips TLS verification
type insecureTransport struct{}

func (t *insecureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// This is a simplified implementation
	// In practice, you'd want to create a proper transport with TLS config
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return transport.RoundTrip(req)
}

// buildAuthOptions creates authentication options similar to syft's approach
func (id *ImageDownloader) buildAuthOptions(ctx context.Context, options domain.RegistryOptions) []remote.Option {
	authOptions := []remote.Option{}

	// Set platform only if explicitly specified in options
	if options.Platform != "" {
		platform, err := v1.ParsePlatform(options.Platform)
		if err != nil {
			logger.L().Warning("failed to parse platform, skipping platform specification",
				helpers.String("platform", options.Platform),
				helpers.Error(err))
		} else {
			authOptions = append(authOptions, remote.WithPlatform(*platform))
			logger.L().Debug("using specified platform",
				helpers.String("platform", options.Platform))
		}
	}

	// Set up registry authentication similar to syft
	if len(options.Credentials) > 0 {
		// Find the first matching credential
		for _, cred := range options.Credentials {
			var authenticator authn.Authenticator
			if cred.Token != "" {
				authenticator = &authn.Bearer{Token: cred.Token}
				logger.L().Debug("using token authentication", helpers.String("authority", cred.Authority))
			} else if cred.Username != "" && cred.Password != "" {
				authenticator = &authn.Basic{
					Username: cred.Username,
					Password: cred.Password,
				}
				logger.L().Debug("using basic authentication",
					helpers.String("authority", cred.Authority),
					helpers.String("username", cred.Username))
			}
			if authenticator != nil {
				authOptions = append(authOptions, remote.WithAuth(authenticator))
				break // Use first valid credential like syft does
			}
		}
	}

	// Set up transport options
	if options.InsecureSkipTLSVerify {
		authOptions = append(authOptions, remote.WithTransport(&insecureTransport{}))
		logger.L().Debug("using insecure transport (skip TLS verify)")
	}

	// Add context - timeout is already handled at the method call level
	authOptions = append(authOptions, remote.WithContext(ctx))

	return authOptions
}

// buildAuthOptionsWithoutCredentials creates auth options without credentials for retry attempts
func (id *ImageDownloader) buildAuthOptionsWithoutCredentials(ctx context.Context, options domain.RegistryOptions) []remote.Option {
	authOptions := []remote.Option{}

	// Set platform only if explicitly specified in options
	if options.Platform != "" {
		platform, err := v1.ParsePlatform(options.Platform)
		if err == nil {
			authOptions = append(authOptions, remote.WithPlatform(*platform))
		}
	}

	// Set up transport options
	if options.InsecureSkipTLSVerify {
		authOptions = append(authOptions, remote.WithTransport(&insecureTransport{}))
	}

	// Use anonymous auth explicitly
	authOptions = append(authOptions, remote.WithAuth(authn.Anonymous))

	// Add context - timeout is already handled at the method call level
	authOptions = append(authOptions, remote.WithContext(ctx))

	return authOptions
}
