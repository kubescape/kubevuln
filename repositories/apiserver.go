package repositories

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/distribution/distribution/reference"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
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

func (a *APIServerStore) GetCVE(ctx context.Context, imageID, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (cve domain.CVEManifest, err error) {
	manifest, err := a.StorageClient.VulnerabilityManifests(a.Namespace).Get(ctx, imageID, metav1.GetOptions{})
	if err != nil {
		return domain.CVEManifest{}, err
	}
	return domain.CVEManifest{
		ImageID:            manifest.Name,
		SBOMCreatorVersion: "",
		CVEScannerVersion:  manifest.Spec.Metadata.Tool.Version,
		CVEDBVersion:       manifest.Spec.Metadata.Tool.DatabaseVersion,
		Content:            &manifest.Spec.Payload,
	}, nil
}

func (a *APIServerStore) StoreCVE(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error {
	manifest := v1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{
			Name: cve.ImageID,
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

// we're guaranteed to have a digest in the imageID by the operator
func hashFromImageID(imageID string) string {
	return strings.Split(reference.ReferenceRegexp.FindStringSubmatch(imageID)[3], ":")[1]
}

func (a *APIServerStore) GetSBOM(ctx context.Context, imageID, SBOMCreatorVersion string) (sbom domain.SBOM, err error) {
	manifest, err := a.StorageClient.SBOMSPDXv2p3s(a.Namespace).Get(ctx, hashFromImageID(imageID), metav1.GetOptions{})
	if err != nil {
		return domain.SBOM{}, err
	}
	return domain.SBOM{
		ID:                 manifest.Annotations[domain.ImageIDKey],
		SBOMCreatorVersion: manifest.Spec.Metadata.Tool.Version,
		Content:            &manifest.Spec.SPDX,
	}, nil
}

func hashFromInstanceID(instanceID string) string {
	hash := sha256.Sum256([]byte(instanceID))
	return hex.EncodeToString(hash[:])
}

func instanceIDFromLabels(labels map[string]string) string {
	return "" // TODO: implement
}

func (a *APIServerStore) GetSBOMp(ctx context.Context, instanceID, SBOMCreatorVersion string) (sbom domain.SBOM, err error) {
	manifest, err := a.StorageClient.SBOMSPDXv2p3Filtereds(a.Namespace).Get(ctx, hashFromImageID(instanceID), metav1.GetOptions{})
	if err != nil {
		return domain.SBOM{}, err
	}
	return domain.SBOM{
		ID:                 instanceIDFromLabels(manifest.Labels),
		SBOMCreatorVersion: manifest.Spec.Metadata.Tool.Version,
		Content:            &manifest.Spec.SPDX,
	}, nil
}

func (a *APIServerStore) StoreSBOM(ctx context.Context, sbom domain.SBOM) error {
	manifest := v1beta1.SBOMSPDXv2p3{
		ObjectMeta: metav1.ObjectMeta{
			Name: hashFromImageID(sbom.ID),
			Annotations: map[string]string{
				domain.ImageIDKey: sbom.ID,
			},
		},
		Spec: v1beta1.SBOMSPDXv2p3Spec{
			Metadata: v1beta1.SPDXMeta{
				Tool: v1beta1.ToolMeta{
					Name:    sbom.SBOMCreatorName,
					Version: sbom.SBOMCreatorVersion,
				},
				Report: v1beta1.ReportMeta{},
			},
			SPDX: *sbom.Content,
		},
		Status: v1beta1.SBOMSPDXv2p3Status{}, // TODO add timeout information here
	}
	_, err := a.StorageClient.SBOMSPDXv2p3s(a.Namespace).Create(ctx, &manifest, metav1.CreateOptions{})
	return err
}

// to be used for tests only
func (a *APIServerStore) storeSBOMp(ctx context.Context, sbom domain.SBOM) error {
	manifest := v1beta1.SBOMSPDXv2p3Filtered{
		ObjectMeta: metav1.ObjectMeta{
			Name: hashFromInstanceID(sbom.ID),
		},
		Spec: v1beta1.SBOMSPDXv2p3Spec{
			SPDX: *sbom.Content,
		},
	}
	_, err := a.StorageClient.SBOMSPDXv2p3Filtereds(a.Namespace).Create(ctx, &manifest, metav1.CreateOptions{})
	return err
}
