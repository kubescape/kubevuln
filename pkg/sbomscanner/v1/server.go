package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/DmitriyVTitov/size"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format/syftjson"
	sbomcataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/eapache/go-resiliency/deadline"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	pb "github.com/kubescape/kubevuln/pkg/sbomscanner/v1/proto"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"golang.org/x/oauth2/google"
)

func isGCPRegistry(imageID string) bool {
	host, _, _ := strings.Cut(imageID, "/")
	return host == "gcr.io" || strings.HasSuffix(host, ".gcr.io") || strings.HasSuffix(host, "-docker.pkg.dev")
}

// isRegistryRateLimited reports whether err is (or wraps) a registry 429 response.
func isRegistryRateLimited(err error) bool {
	var transportErr *transport.Error
	return errors.As(err, &transportErr) && transportErr.StatusCode == http.StatusTooManyRequests
}

func gcpCredentials(ctx context.Context) (*image.RegistryCredentials, error) {
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, err
	}
	token, err := creds.TokenSource.Token()
	if err != nil {
		return nil, err
	}
	return &image.RegistryCredentials{Username: "oauth2accesstoken", Password: token.AccessToken}, nil
}

// gcpCredsFn is an indirection over gcpCredentials so resolveSource can be
// unit-tested without a live GCP environment.
var gcpCredsFn = gcpCredentials

// sourceGetter abstracts the syft.GetSource call so the fallback ordering in
// resolveSource is testable with a scripted implementation.
type sourceGetter func(ctx context.Context, ref string, opts *image.RegistryOptions) (source.Source, error)

// resolveSource downloads an image source, applying the MANIFEST_UNKNOWN and
// 401/ADC/anonymous fallbacks in order. It mirrors the retry chain in
// adapters/v1/syft.go so the sidecar and in-process adapters behave the same.
func resolveSource(ctx context.Context, get sourceGetter, imageID, imageTag string, opts image.RegistryOptions) (source.Source, error) {
	pullRef := imageID
	src, err := get(ctx, pullRef, &opts)
	if err != nil && strings.Contains(err.Error(), "MANIFEST_UNKNOWN") {
		logger.L().Debug("got MANIFEST_UNKNOWN, retrying with imageTag",
			helpers.String("imageTag", imageTag),
			helpers.String("imageID", imageID))
		pullRef = imageTag
		src, err = get(ctx, pullRef, &opts)
	}
	if err != nil && strings.Contains(err.Error(), "401 Unauthorized") {
		unauthorizedErr := err
		if isGCPRegistry(imageID) {
			if gcpCreds, gcpErr := gcpCredsFn(ctx); gcpErr != nil {
				logger.L().Debug("GCP ADC unavailable, falling back to anonymous",
					helpers.Error(gcpErr),
					helpers.String("imageID", imageID))
			} else {
				opts.Credentials = []image.RegistryCredentials{*gcpCreds}
				src, err = get(ctx, pullRef, &opts)
			}
		}
		// If GCP ADC was not attempted, succeeded in auth but still got 401, or
		// the image is not a GCP registry, fall back to anonymous access.
		if err != nil {
			logger.L().Debug("retrying without credentials",
				helpers.String("imageID", imageID))
			opts.Credentials = nil
			src, err = get(ctx, pullRef, &opts)
			if err != nil && !strings.Contains(err.Error(), "401 Unauthorized") {
				err = fmt.Errorf("%w (anonymous fallback failed: %v)", unauthorizedErr, err)
			}
		}
	}
	return src, err
}

type scannerServer struct {
	pb.UnimplementedSBOMScannerServer
	mu      sync.Mutex
	version string
}

// NewScannerServer creates a new gRPC scanner server.
func NewScannerServer() pb.SBOMScannerServer {
	return &scannerServer{
		version: packageVersion("github.com/anchore/syft"),
	}
}

func (s *scannerServer) CreateSBOM(ctx context.Context, req *pb.CreateSBOMRequest) (*pb.CreateSBOMResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// imageID is already the final, normalized pull reference. The SidecarSBOMAdapter
	// normalizes it (NormalizeImageID) before sending the request - that is the single
	// normalization point. Do not normalize again here: re-normalizing an
	// already-complete reference corrupts it (e.g. into repo@sha256:<tag> when no
	// digest is known, which then fails to parse).
	imageID := req.ImageId
	imageTag := req.ImageTag

	// Parse platform for multi-arch image resolution.
	// The platform specifier uses OCI format: "os/arch[/variant]" (e.g. "linux/amd64").
	// If only an architecture is provided (e.g. "amd64"), we prepend "linux/".
	platformStr := req.Platform
	if platformStr == "" {
		platformStr = runtime.GOARCH
	}
	if !strings.Contains(platformStr, "/") {
		platformStr = "linux/" + platformStr
	}
	imgPlatform, err := image.NewPlatform(platformStr)
	if err != nil {
		return nil, fmt.Errorf("invalid platform %q: %w", platformStr, err)
	}

	// Build registry credentials
	credentials := make([]image.RegistryCredentials, len(req.Credentials))
	for i, c := range req.Credentials {
		credentials[i] = image.RegistryCredentials{
			Authority: c.Authority,
			Username:  c.Username,
			Password:  c.Password,
			Token:     c.Token,
		}
	}
	registryOptions := image.RegistryOptions{
		InsecureSkipTLSVerify: req.InsecureSkipTlsVerify,
		InsecureUseHTTP:       req.InsecureUseHttp,
		Credentials:           credentials,
	}

	// Prepare temp dir for stereoscope
	t := file.NewTempDirGenerator("stereoscope")
	defer func() {
		if err := t.Cleanup(); err != nil {
			logger.L().Warning("failed to cleanup temp dir", helpers.Error(err),
				helpers.String("imageID", imageID))
		}
	}()

	// Download image from registry
	logger.L().Debug("downloading image", helpers.String("imageID", imageID))
	src, err := resolveSource(ctx, func(_ context.Context, ref string, opts *image.RegistryOptions) (source.Source, error) {
		// Pulls intentionally run on a detached context (see #421); the request ctx is used only for gcpCredentials inside resolveSource.
		ctxWithSize := context.WithValue(context.Background(), image.MaxImageSize, req.MaxImageSize)
		return syft.GetSource(ctxWithSize, ref,
			syft.DefaultGetSourceConfig().WithRegistryOptions(opts).WithPlatform(imgPlatform).WithSources("registry"))
	}, imageID, imageTag, registryOptions)

	switch {
	case err != nil && (errors.Is(err, image.ErrImageTooLarge) || strings.Contains(err.Error(), image.ErrImageTooLarge.Error())):
		logger.L().Warning("Image exceeds size limit",
			helpers.Int("maxImageSize", int(req.MaxImageSize)),
			helpers.String("imageID", imageID))
		return &pb.CreateSBOMResponse{
			Status:       helpersv1.TooLarge,
			StatusReason: domain.ReasonImageTooLarge,
		}, nil
	case err != nil && strings.Contains(err.Error(), "401 Unauthorized"):
		return &pb.CreateSBOMResponse{
			Status:       helpersv1.Unauthorize,
			ErrorMessage: err.Error(),
		}, nil
	case err != nil && isRegistryRateLimited(err):
		// StatusReason travels over gRPC as a plain string, so the caller (adapters/v1
		// SidecarSBOMAdapter.CreateSBOM) reconstructs a *transport.Error from it to keep
		// ScanService.checkCreateSBOM's errors.As(...) check working the same way it does
		// for the in-process syft adapter.
		return &pb.CreateSBOMResponse{
			ErrorMessage: err.Error(),
			StatusReason: domain.ReasonTooManyRequests,
		}, nil
	case err != nil:
		return &pb.CreateSBOMResponse{
			ErrorMessage: err.Error(),
		}, nil
	}

	// Generate SBOM with timeout
	var syftSBOM *sbom.SBOM
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	dl := deadline.New(timeout)
	err = dl.Run(func(stopper <-chan struct{}) error {
		defer func(src source.Source) {
			if err := src.Close(); err != nil {
				logger.L().Warning("failed to close source", helpers.Error(err),
					helpers.String("imageID", imageID))
			}
		}(src)

		logger.L().Debug("generating SBOM", helpers.String("imageID", imageID))
		cfg := syft.DefaultCreateSBOMConfig()
		cfg.ToolName = "syft"
		cfg.ToolVersion = s.version
		if req.EnableEmbeddedSboms {
			cfg.WithCatalogers(pkgcataloging.NewCatalogerReference(
				sbomcataloger.NewCataloger(), []string{pkgcataloging.ImageTag}))
		}
		// NOTE: Syft's cataloguers do not support context cancellation (see
		// https://github.com/anchore/syft/issues/3705). The deadline.Run wrapper
		// will return ErrTimedOut, but the Syft goroutine may continue until it
		// finishes naturally. This is an accepted tradeoff — the sidecar's memory
		// limit will OOM-kill the container if resource usage grows unbounded.
		syftSBOM, err = syft.CreateSBOM(context.Background(), src, cfg)
		if err != nil {
			return fmt.Errorf("failed to generate SBOM: %w", err)
		}
		return nil
	})

	switch {
	case errors.Is(err, deadline.ErrTimedOut):
		logger.L().Warning("Syft timed out", helpers.String("imageID", imageID))
		return &pb.CreateSBOMResponse{
			Status: helpersv1.Incomplete,
		}, nil
	case err == nil:
		// continue
	default:
		return &pb.CreateSBOMResponse{
			Status:       helpersv1.Incomplete,
			ErrorMessage: err.Error(),
		}, nil
	}

	// Strip the SBOM to reduce size
	v1beta1.StripSBOM(syftSBOM)

	// Check in-memory size
	sz := size.Of(syftSBOM)
	if sz > int(req.MaxSbomSize) {
		logger.L().Warning("SBOM exceeds size limit",
			helpers.Int("maxSBOMSize", int(req.MaxSbomSize)),
			helpers.Int("size", sz),
			helpers.String("imageID", imageID))
		return &pb.CreateSBOMResponse{
			Status:       helpersv1.TooLarge,
			SbomSize:     int64(sz),
			StatusReason: domain.ReasonSBOMTooLarge,
		}, nil
	}

	// Convert to SyftDocument and serialize
	doc := syftToDomain(*syftSBOM)
	docBytes, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SBOM: %w", err)
	}

	logger.L().Info("SBOM scan completed",
		helpers.String("imageID", imageID),
		helpers.Int("sbomSize", len(docBytes)),
		helpers.Int("packages", len(doc.Artifacts)))

	return &pb.CreateSBOMResponse{
		Status:       helpersv1.Learning,
		SbomDocument: docBytes,
		SbomSize:     int64(sz),
	}, nil
}

func (s *scannerServer) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{
		Version: s.version,
		Ready:   true,
	}, nil
}

// syftToDomain converts a Syft SBOM to a v1beta1.SyftDocument.
// This is the same logic as SyftAdapter.syftToDomain.
func syftToDomain(sbomSBOM sbom.SBOM) *v1beta1.SyftDocument {
	doc := syftjson.ToFormatModel(sbomSBOM, syftjson.EncoderConfig{
		Pretty: false,
		Legacy: false,
	})

	b, err := json.Marshal(doc)
	if err != nil {
		return nil
	}

	var syftDoc *v1beta1.SyftDocument
	if err := json.Unmarshal(b, &syftDoc); err != nil {
		return nil
	}
	for i := range syftDoc.Artifacts {
		for j := range doc.Artifacts {
			if syftDoc.Artifacts[i].ID == doc.Artifacts[j].ID {
				syftDoc.Artifacts[i].MetadataType = doc.Artifacts[j].MetadataType
				if b, err := json.Marshal(doc.Artifacts[j].Metadata); err == nil {
					syftDoc.Artifacts[i].Metadata = b
				}
				break
			}
		}
	}

	return syftDoc
}

func packageVersion(name string) string {
	bi, ok := debug.ReadBuildInfo()
	if ok {
		for _, dep := range bi.Deps {
			if dep.Path == name {
				return dep.Version
			}
		}
	}
	return "unknown"
}
