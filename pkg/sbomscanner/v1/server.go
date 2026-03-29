package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	sbomcataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/eapache/go-resiliency/deadline"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	pb "github.com/kubescape/kubevuln/pkg/sbomscanner/v1/proto"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/opencontainers/go-digest"
)

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

	imageID := req.ImageId
	imageTag := req.ImageTag

	// Normalize image ID (same logic as SyftAdapter)
	if imageTag != "" {
		imageID = normalizeImageID(imageID, imageTag)
	}

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
	ctxWithSize := context.WithValue(context.Background(), image.MaxImageSize, req.MaxImageSize)
	src, err := syft.GetSource(ctxWithSize, imageID,
		syft.DefaultGetSourceConfig().WithRegistryOptions(&registryOptions).WithPlatform(imgPlatform).WithSources("registry"))

	if err != nil && strings.Contains(err.Error(), "MANIFEST_UNKNOWN") {
		logger.L().Debug("got MANIFEST_UNKNOWN, retrying with imageTag",
			helpers.String("imageTag", imageTag),
			helpers.String("imageID", imageID))
		src, err = syft.GetSource(ctxWithSize, imageTag,
			syft.DefaultGetSourceConfig().WithRegistryOptions(&registryOptions).WithPlatform(imgPlatform).WithSources("registry"))
	}

	if err != nil && strings.Contains(err.Error(), "401 Unauthorized") {
		logger.L().Debug("got 401, retrying without credentials",
			helpers.String("imageID", imageID))
		registryOptions.Credentials = nil
		src, err = syft.GetSource(ctxWithSize, imageID,
			syft.DefaultGetSourceConfig().WithRegistryOptions(&registryOptions).WithPlatform(imgPlatform).WithSources("registry"))
	}

	switch {
	case err != nil && strings.Contains(err.Error(), image.ErrImageTooLarge.Error()):
		logger.L().Warning("Image exceeds size limit",
			helpers.Int("maxImageSize", int(req.MaxImageSize)),
			helpers.String("imageID", imageID))
		return &pb.CreateSBOMResponse{
			Status: helpersv1.Incomplete,
		}, nil
	case err != nil && strings.Contains(err.Error(), "401 Unauthorized"):
		return &pb.CreateSBOMResponse{
			Status:       helpersv1.Unauthorize,
			ErrorMessage: err.Error(),
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
			Status:   helpersv1.TooLarge,
			SbomSize: int64(sz),
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

const digestDelim = "@"

// normalizeImageID is the same logic as the top-level NormalizeImageID in adapters/v1/syft.go.
func normalizeImageID(imageID, imageTag string) string {
	if imageID == "" {
		return imageTag
	}

	// try to parse imageID as a full digest
	if newDigest, err := name.NewDigest(imageID); err == nil {
		return newDigest.String()
	}
	// if it's not a full digest, use imageTag as a reference
	tag, err := name.ParseReference(imageTag)
	if err != nil {
		return ""
	}

	// and append imageID as a digest
	parts := strings.Split(imageID, digestDelim)
	if len(parts) > 1 {
		imageID = parts[len(parts)-1]
	}
	prefix := digest.Canonical.String() + ":"
	if !strings.HasPrefix(imageID, prefix) {
		imageID = prefix + imageID
	}
	return tag.Context().String() + "@" + imageID
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
