package repositories

import (
	"context"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// APIServerStore implements both CVERepository and SBOMRepository with in-cluster storage (apiserver) to be used for production
type APIServerStore struct {
	Clientset *versioned.Clientset
	Namespace string
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
		Clientset: clientset,
		Namespace: namespace,
	}, nil
}

func (a *APIServerStore) GetCVE(ctx context.Context, imageID, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (cve domain.CVEManifest, err error) {
	manifest, err := a.Clientset.SpdxV1beta1().VulnerabilityManifests(a.Namespace).Get(ctx, imageID, metav1.GetOptions{})
	return domain.CVEManifest{
		ImageID:            manifest.Name,
		SBOMCreatorVersion: "",
		CVEScannerVersion:  manifest.Spec.Metadata.Tool.Version,
		CVEDBVersion:       manifest.Spec.Metadata.Tool.DatabaseVersion,
		Content:            &manifest.Spec.Payload,
	}, err
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
	_, err := a.Clientset.SpdxV1beta1().VulnerabilityManifests(a.Namespace).Create(ctx, &manifest, metav1.CreateOptions{})
	return err
}

func (a *APIServerStore) GetSBOM(ctx context.Context, imageID, SBOMCreatorVersion string) (sbom domain.SBOM, err error) {
	manifest, err := a.Clientset.SpdxV1beta1().SBOMSPDXv2p3s(a.Namespace).Get(ctx, imageID, metav1.GetOptions{})
	return domain.SBOM{
		ImageID:            manifest.Name,
		SBOMCreatorVersion: manifest.Spec.Metadata.Tool.Version,
		Content:            &manifest.Spec.SPDX,
	}, err
}

func (a *APIServerStore) GetSBOMp(ctx context.Context, instanceID, SBOMCreatorVersion string) (sbom domain.SBOM, err error) {
	manifest, err := a.Clientset.SpdxV1beta1().SBOMSPDXv2p3Filtereds(a.Namespace).Get(ctx, instanceID, metav1.GetOptions{})
	return domain.SBOM{
		ImageID:            manifest.Name,
		SBOMCreatorVersion: manifest.Spec.Metadata.Tool.Version,
		Content:            &manifest.Spec.SPDX,
	}, err
}

func (a *APIServerStore) StoreSBOM(ctx context.Context, sbom domain.SBOM) error {
	manifest := v1beta1.SBOMSPDXv2p3{
		ObjectMeta: metav1.ObjectMeta{
			Name: sbom.ImageID,
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
	_, err := a.Clientset.SpdxV1beta1().SBOMSPDXv2p3s(a.Namespace).Create(ctx, &manifest, metav1.CreateOptions{})
	return err
}

func (a *APIServerStore) StoreSBOMp(ctx context.Context, sbom domain.SBOM) error {
	manifest := v1beta1.SBOMSPDXv2p3Filtered{
		ObjectMeta: metav1.ObjectMeta{
			Name: sbom.ImageID,
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
	_, err := a.Clientset.SpdxV1beta1().SBOMSPDXv2p3Filtereds(a.Namespace).Create(ctx, &manifest, metav1.CreateOptions{})
	return err
}
