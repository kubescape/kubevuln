package repositories

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/distribution/distribution/reference"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
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

func NewFakeAPIServerStorage(namespace string) *APIServerStore {
	return &APIServerStore{
		StorageClient: fake.NewSimpleClientset().SpdxV1beta1(),
		Namespace:     namespace,
	}
}

// we're guaranteed to have a digest in the imageID by the operator
func hashFromImageID(imageID string) string {
	return strings.Split(reference.ReferenceRegexp.FindStringSubmatch(imageID)[3], ":")[1]
}

func hashFromInstanceID(instanceID string) string {
	hash := sha256.Sum256([]byte(instanceID))
	return hex.EncodeToString(hash[:])
}

func labelsFromInstanceID(instanceID string) map[string]string {
	return map[string]string{
		labelKind:      wlid.GetKindFromWlid(instanceID),
		labelName:      wlid.GetNameFromWlid(instanceID),
		labelNamespace: wlid.GetNamespaceFromWlid(instanceID),
	}
}

func (a *APIServerStore) GetCVE(ctx context.Context, imageID, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (cve domain.CVEManifest, err error) {
	if imageID == "" {
		return domain.CVEManifest{}, nil
	}
	manifest, err := a.StorageClient.VulnerabilityManifests(a.Namespace).Get(ctx, hashFromImageID(imageID), metav1.GetOptions{})
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to get CVE manifest from apiserver", helpers.Error(err), helpers.String("ID", imageID))
		return domain.CVEManifest{}, nil
	}
	// discard the manifest if it was created by an older version of the scanner
	// TODO: also check SBOMCreatorVersion ?
	if manifest.Spec.Metadata.Tool.Version != CVEScannerVersion || manifest.Spec.Metadata.Tool.DatabaseVersion != CVEDBVersion {
		return domain.CVEManifest{}, nil
	}
	return domain.CVEManifest{
		ID:                 imageID,
		SBOMCreatorVersion: SBOMCreatorVersion,
		CVEScannerVersion:  CVEScannerVersion,
		CVEDBVersion:       CVEDBVersion,
		Content:            &manifest.Spec.Payload,
	}, nil
}

func (a *APIServerStore) StoreCVE(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error {
	if cve.ID == "" {
		return nil
	}
	name := hashFromImageID(cve.ID)
	annotations := map[string]string{domain.ImageTagKey: cve.ID}
	if withRelevancy {
		name = hashFromInstanceID(cve.ID)
		annotations = map[string]string{
			domain.InstanceIDKey: cve.ID,
			domain.WlidKey:       cve.Wlid,
		}
	}
	manifest := v1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
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
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to store CVE manifest into apiserver", helpers.Error(err), helpers.String("ID", cve.ID))
	}
	return nil
}

func (a *APIServerStore) GetSBOM(ctx context.Context, imageID, SBOMCreatorVersion string) (sbom domain.SBOM, err error) {
	if imageID == "" {
		return domain.SBOM{}, nil
	}
	manifest, err := a.StorageClient.SBOMSPDXv2p3s(a.Namespace).Get(ctx, hashFromImageID(imageID), metav1.GetOptions{})
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to get SBOM from apiserver", helpers.Error(err), helpers.String("ID", imageID))
		return domain.SBOM{}, nil
	}
	// discard the manifest if it was created by an older version of the scanner
	if manifest.Spec.Metadata.Tool.Version != SBOMCreatorVersion {
		return domain.SBOM{}, nil
	}
	result := domain.SBOM{
		ID:                 imageID,
		SBOMCreatorVersion: SBOMCreatorVersion,
		Content:            &manifest.Spec.SPDX,
	}
	if status, ok := manifest.Annotations[domain.StatusKey]; ok {
		result.Status = status
	}
	return result, nil
}

func (a *APIServerStore) GetSBOMp(ctx context.Context, instanceID, SBOMCreatorVersion string) (sbom domain.SBOM, err error) {
	if instanceID == "" {
		return domain.SBOM{}, nil
	}
	manifest, err := a.StorageClient.SBOMSPDXv2p3Filtereds(a.Namespace).Get(ctx, hashFromInstanceID(instanceID), metav1.GetOptions{})
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to get relevant SBOM from apiserver", helpers.Error(err), helpers.String("ID", instanceID))
		return domain.SBOM{}, nil
	}
	// discard the manifest if it was created by an older version of the scanner
	if manifest.Spec.Metadata.Tool.Version != SBOMCreatorVersion {
		return domain.SBOM{}, nil
	}
	result := domain.SBOM{
		ID:                 instanceID,
		SBOMCreatorVersion: SBOMCreatorVersion,
		Content:            &manifest.Spec.SPDX,
	}
	if status, ok := manifest.Annotations[domain.StatusKey]; ok {
		result.Status = status
	}
	return result, nil
}

func (a *APIServerStore) StoreSBOM(ctx context.Context, sbom domain.SBOM) error {
	if sbom.ID == "" {
		return nil
	}
	manifest := v1beta1.SBOMSPDXv2p3{
		ObjectMeta: metav1.ObjectMeta{
			Name: hashFromImageID(sbom.ID),
			Annotations: map[string]string{
				domain.ImageTagKey: sbom.ID,
				domain.StatusKey:   sbom.Status,
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
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to store SBOM into apiserver", helpers.Error(err), helpers.String("ID", sbom.ID))
	}
	return nil
}
