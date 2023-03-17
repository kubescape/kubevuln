package repositories

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/distribution/distribution/reference"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const (
	labelKind      = "kubescape.io/workload-kind"
	labelName      = "kubescape.io/workload-name"
	labelNamespace = "kubescape.io/workload-namespace"
)

// APIServerStore implements both CVERepository and SBOMRepository with in-cluster storage (apiserver) to be used for production
type APIServerStore struct {
	StorageClient spdxv1beta1.SpdxV1beta1Interface
	Namespace     string
}

var _ ports.CVERepository = (*APIServerStore)(nil)

var _ ports.SBOMRepository = (*APIServerStore)(nil)

// NewAPIServerStorage initializes the APIServerStore struct
func NewAPIServerStorage(namespace string) (*APIServerStore, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := versioned.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &APIServerStore{
		StorageClient: clientset.SpdxV1beta1(),
		Namespace:     namespace,
	}, nil
}

// we're guaranteed to have a digest in the imageID by the operator
func hashFromImageID(imageID string) string {
	return strings.Split(reference.ReferenceRegexp.FindStringSubmatch(imageID)[3], ":")[1]
}

func hashFromInstanceID(instanceID string) string {
	hash := sha256.Sum256([]byte(instanceID))
	return hex.EncodeToString(hash[:])
}

// apiVersion-v1/namespace-default/kind-Deployment/name-nginx/resourceVersion-153294/containerName-nginx
func instanceIDFromLabels(labels map[string]string) string {
	return fmt.Sprintf("apiVersion-%s/namespace-%s/kind-%s/name-%s/resourceVersion-%s/containerName-%s",
		"v1", labels[labelNamespace], labels[labelKind], labels[labelName], labels["TODO resourceVersion"], labels["TODO containerName"])
}

func labelsFromInstanceID(instanceID string) map[string]string {
	return map[string]string{
		labelKind:      wlid.GetKindFromWlid(instanceID),
		labelName:      wlid.GetNameFromWlid(instanceID),
		labelNamespace: wlid.GetNamespaceFromWlid(instanceID),
	}
}

func (a *APIServerStore) GetCVE(ctx context.Context, imageID, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (cve domain.CVEManifest, err error) {
	manifest, err := a.StorageClient.VulnerabilityManifests(a.Namespace).Get(ctx, hashFromImageID(imageID), metav1.GetOptions{})
	if err != nil {
		return domain.CVEManifest{}, err
	}
	return domain.CVEManifest{
		ImageID:            manifest.Annotations[domain.ImageIDKey],
		SBOMCreatorVersion: "",
		CVEScannerVersion:  manifest.Spec.Metadata.Tool.Version,
		CVEDBVersion:       manifest.Spec.Metadata.Tool.DatabaseVersion,
		Content:            &manifest.Spec.Payload,
	}, nil
}

func (a *APIServerStore) StoreCVE(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error {
	manifest := v1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{
			Name: hashFromImageID(cve.ImageID),
			Annotations: map[string]string{
				domain.ImageIDKey: cve.ImageID,
			},
		},
		Spec: v1beta1.VulnerabilityManifestSpec{
			Metadata: v1beta1.VulnerabilityManifestMeta{
				WithRelevancy: withRelevancy,
				Tool: v1beta1.VulnerabilityManifestToolMeta{
					Name:            cve.CVEScannerName,
					Version:         cve.CVEScannerVersion,
					DatabaseVersion: cve.CVEDBVersion,
				},
			},
			Payload: *cve.Content,
		},
	}
	_, err := a.StorageClient.VulnerabilityManifests(a.Namespace).Create(ctx, &manifest, metav1.CreateOptions{})
	return err
}

func (a *APIServerStore) GetSBOM(ctx context.Context, imageID, SBOMCreatorVersion string) (sbom domain.SBOM, err error) {
	manifest, err := a.StorageClient.SBOMSPDXv2p3s(a.Namespace).Get(ctx, hashFromImageID(imageID), metav1.GetOptions{})
	if err != nil {
		return domain.SBOM{}, err
	}
	result := domain.SBOM{
		ID:                 manifest.Annotations[domain.ImageIDKey],
		SBOMCreatorVersion: manifest.Spec.Metadata.Tool.Version,
		Content:            &manifest.Spec.SPDX,
	}
	if status, ok := manifest.Annotations[domain.StatusKey]; ok {
		result.Status = status
	}
	return result, nil
}

func (a *APIServerStore) GetSBOMp(ctx context.Context, instanceID, SBOMCreatorVersion string) (sbom domain.SBOM, err error) {
	manifest, err := a.StorageClient.SBOMSPDXv2p3Filtereds(a.Namespace).Get(ctx, hashFromInstanceID(instanceID), metav1.GetOptions{})
	if err != nil {
		return domain.SBOM{}, err
	}
	result := domain.SBOM{
		ID:                 instanceIDFromLabels(manifest.Labels),
		SBOMCreatorVersion: manifest.Spec.Metadata.Tool.Version,
		Content:            &manifest.Spec.SPDX,
	}
	if status, ok := manifest.Annotations[domain.StatusKey]; ok {
		result.Status = status
	}
	return result, nil
}

func (a *APIServerStore) StoreSBOM(ctx context.Context, sbom domain.SBOM) error {
	manifest := v1beta1.SBOMSPDXv2p3{
		ObjectMeta: metav1.ObjectMeta{
			Name: hashFromImageID(sbom.ID),
			Annotations: map[string]string{
				domain.ImageIDKey: sbom.ID,
				domain.StatusKey:  sbom.Status,
			},
		},
		Spec: v1beta1.SBOMSPDXv2p3Spec{
			Metadata: v1beta1.SPDXMeta{
				Tool: v1beta1.ToolMeta{
					Name:    sbom.SBOMCreatorName,
					Version: sbom.SBOMCreatorVersion,
				},
			},
			SPDX: *sbom.Content,
		},
		Status: v1beta1.SBOMSPDXv2p3Status{}, // TODO move timeout information here
	}
	created, err := time.Parse(time.RFC3339, sbom.Content.CreationInfo.Created)
	if err != nil {
		manifest.Spec.Metadata.Report.CreatedAt.Time = created
	}
	_, err = a.StorageClient.SBOMSPDXv2p3s(a.Namespace).Create(ctx, &manifest, metav1.CreateOptions{})
	return err
}
