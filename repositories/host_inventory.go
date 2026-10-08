package repositories

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"golang.org/x/mod/semver"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

var _ ports.HostSBOMRepository = (*APIServerStore)(nil)
var hostIdentityReplacer = regexp.MustCompile("[@:/ ._]")

// hostInventoryIdentifier mirrors node-agent's collisionResistantLabel. Hash
// the raw node name before the producer's lossy sanitize/truncate operation.
func hostInventoryIdentifier(prefix, node string) string {
	sum := sha256.Sum256([]byte(node))
	suffix := hex.EncodeToString(sum[:])[:32]
	base := hostIdentityReplacer.ReplaceAllString(strings.ToLower(node), "-")
	if len(base) > 63 {
		base = base[:63]
	}
	base = strings.TrimSuffix(base, "-")
	maxBaseLen := 63 - len(prefix) - 1 - len(suffix)
	if len(base) > maxBaseLen {
		base = strings.TrimRight(base[:maxBaseLen], "-")
	}
	return prefix + base + "-" + suffix
}

// GetHostSBOM fetches exactly the producer object for node, without image-version
// invalidation or any writes to producer-owned storage.
func (a *APIServerStore) GetHostSBOM(ctx context.Context, node string) (domain.SBOM, error) {
	if err := ctx.Err(); err != nil {
		return domain.SBOM{}, err
	}
	if node == "" || len(validation.IsDNS1123Subdomain(node)) != 0 {
		return domain.SBOM{}, fmt.Errorf("%w: invalid node name", domain.ErrHostInventoryUnavailable)
	}
	name := hostInventoryIdentifier("host-", node)
	manifest, err := a.StorageClient.SBOMSyfts(a.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if ctx.Err() != nil {
			return domain.SBOM{}, ctx.Err()
		}
		if apierrors.IsNotFound(err) || apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || apierrors.IsServiceUnavailable(err) || apierrors.IsTooManyRequests(err) {
			return domain.SBOM{}, fmt.Errorf("%w: %s: %w", domain.ErrHostInventoryPending, name, err)
		}
		return domain.SBOM{}, fmt.Errorf("get host inventory %s: %w", name, err)
	}
	invalid := func(reason string) (domain.SBOM, error) {
		return domain.SBOM{}, fmt.Errorf("%w: %s: %s", domain.ErrHostInventoryUnavailable, name, reason)
	}
	identity := hostInventoryIdentifier("", node)
	if manifest.Name != name || manifest.Labels["kubescape.io/host"] != identity || manifest.Labels["kubescape.io/node-name"] != identity {
		return invalid("conflicting or missing host identity")
	}
	status := manifest.Annotations[helpersv1.StatusMetadataKey]
	if status == helpersv1.Initializing {
		return domain.SBOM{}, fmt.Errorf("%w: %s is initializing", domain.ErrHostInventoryPending, name)
	}
	if status != helpersv1.Learning {
		return invalid("inventory status " + status)
	}
	doc := &manifest.Spec.Syft
	if doc.SyftSource.Type != "directory" {
		return invalid("source must be directory")
	}
	var source struct {
		Path string `json:"path"`
	}
	if json.Unmarshal(doc.SyftSource.Metadata, &source) != nil || source.Path == "" || !strings.HasPrefix(source.Path, "/") {
		return invalid("malformed directory source metadata")
	}
	version := "v" + strings.TrimPrefix(doc.Schema.Version, "v")
	if !semver.IsValid(version) || semver.Major(version) != "v16" {
		return invalid("unsupported Syft schema " + doc.Schema.Version)
	}
	if doc.Distro.ID == "" || (doc.Distro.VersionID == "" && doc.Distro.Version == "") {
		return invalid("missing distro identity/version")
	}
	if manifest.UID == "" || manifest.ResourceVersion == "" || manifest.Spec.Metadata.Tool.Name == "" || manifest.Spec.Metadata.Tool.Version == "" {
		return invalid("missing inventory provenance")
	}
	owned := manifest.DeepCopy()
	if owned.Annotations == nil {
		owned.Annotations = make(map[string]string)
	}
	owned.Annotations[domain.HostInventoryUIDAnnotationKey] = string(manifest.UID)
	owned.Annotations[domain.HostInventoryResourceVersionAnnotationKey] = manifest.ResourceVersion
	return domain.SBOM{Name: name, Content: &owned.Spec.Syft, Labels: owned.Labels, Annotations: owned.Annotations, Status: status,
		SBOMCreatorName: owned.Spec.Metadata.Tool.Name, SBOMCreatorVersion: owned.Spec.Metadata.Tool.Version}, nil
}
