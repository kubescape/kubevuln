package repositories

import (
	"context"
	"strings"
	"time"

	"github.com/distribution/distribution/reference"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"go.opentelemetry.io/otel"
	"k8s.io/apimachinery/pkg/api/errors"
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

func NewFakeAPIServerStorage(namespace string) *APIServerStore {
	return &APIServerStore{
		StorageClient: fake.NewSimpleClientset().SpdxV1beta1(),
		Namespace:     namespace,
	}
}

// we're guaranteed to have a digest in the imageID by the operator
func hashFromImageID(imageID string) string {
	match := reference.ReferenceRegexp.FindStringSubmatch(imageID)
	if match[3] == "" {
		// just a digest
		return imageID
	}
	return strings.Split(match[3], ":")[1]
}

func (a *APIServerStore) GetCVE(ctx context.Context, imageID, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (cve domain.CVEManifest, err error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetCVE")
	defer span.End()
	if imageID == "" {
		logger.L().Debug("empty image ID provided, skipping CVE retrieval")
		return domain.CVEManifest{}, nil
	}
	manifest, err := a.StorageClient.VulnerabilityManifests(a.Namespace).Get(context.Background(), hashFromImageID(imageID), metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		logger.L().Debug("CVE manifest not found in storage", helpers.String("ID", imageID))
		return domain.CVEManifest{}, nil
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to get CVE manifest from apiserver", helpers.Error(err), helpers.String("ID", imageID))
		return domain.CVEManifest{}, nil
	}
	// discard the manifest if it was created by an older version of the scanner
	// TODO: also check SBOMCreatorVersion ?
	if manifest.Spec.Metadata.Tool.Version != CVEScannerVersion || manifest.Spec.Metadata.Tool.DatabaseVersion != CVEDBVersion {
		logger.L().Debug("discarding CVE manifest with outdated scanner version", helpers.String("ID", imageID), helpers.String("manifest scanner version", manifest.Spec.Metadata.Tool.Version), helpers.String("manifest DB version", manifest.Spec.Metadata.Tool.DatabaseVersion), helpers.String("wanted scanner version", CVEScannerVersion), helpers.String("wanted DB version", CVEDBVersion))
		return domain.CVEManifest{}, nil
	}
	logger.L().Debug("got CVE manifest from storage", helpers.String("ID", imageID))
	return domain.CVEManifest{
		ID:                 imageID,
		SBOMCreatorVersion: SBOMCreatorVersion,
		CVEScannerVersion:  CVEScannerVersion,
		CVEDBVersion:       CVEDBVersion,
		Content:            &manifest.Spec.Payload,
	}, nil
}

func (a *APIServerStore) StoreCVE(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreCVE")
	defer span.End()
	if cve.ID == "" {
		logger.L().Debug("skipping storing CVE manifest with empty ID")
		return nil
	}
	name := hashFromImageID(cve.ID)
	annotations := make(map[string]string)
	if withRelevancy {
		annotations[domain.InstanceIDKey] = cve.ID
		annotations[domain.WlidKey] = cve.Wlid
	} else {
		annotations[domain.ImageTagKey] = cve.ID
	}
	manifest := v1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
			Labels:      cve.Labels,
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
	_, err := a.StorageClient.VulnerabilityManifests(a.Namespace).Create(context.Background(), &manifest, metav1.CreateOptions{})
	switch {
	case errors.IsAlreadyExists(err):
		logger.L().Debug("CVE manifest already exists in storage", helpers.String("ID", cve.ID))
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to store CVE manifest into apiserver", helpers.Error(err), helpers.String("ID", cve.ID))
	default:
		logger.L().Debug("stored CVE manifest in storage", helpers.String("ID", cve.ID))
	}
	return nil
}

func (a *APIServerStore) GetSBOM(ctx context.Context, imageID, SBOMCreatorVersion string) (sbom domain.SBOM, err error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetSBOM")
	defer span.End()
	if imageID == "" {
		logger.L().Debug("empty image ID provided, skipping SBOM retrieval")
		return domain.SBOM{}, nil
	}
	manifest, err := a.StorageClient.SBOMSPDXv2p3s(a.Namespace).Get(context.Background(), hashFromImageID(imageID), metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		logger.L().Debug("SBOM manifest not found in storage", helpers.String("ID", imageID))
		return domain.SBOM{}, nil
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to get SBOM from apiserver", helpers.Error(err), helpers.String("ID", imageID))
		return domain.SBOM{}, nil
	}
	// discard the manifest if it was created by an older version of the scanner
	if manifest.Spec.Metadata.Tool.Version != SBOMCreatorVersion {
		logger.L().Debug("discarding SBOM with outdated scanner version", helpers.String("ID", imageID), helpers.String("manifest scanner version", manifest.Spec.Metadata.Tool.Version), helpers.String("wanted scanner version", SBOMCreatorVersion))
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
	logger.L().Debug("got SBOM from storage", helpers.String("ID", imageID))
	return result, nil
}

func (a *APIServerStore) GetSBOMp(ctx context.Context, instanceID, SBOMCreatorVersion string) (sbom domain.SBOM, err error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetSBOMp")
	defer span.End()
	if instanceID == "" {
		logger.L().Debug("empty instance ID provided, skipping relevant SBOM retrieval")
		return domain.SBOM{}, nil
	}
	manifest, err := a.StorageClient.SBOMSPDXv2p3Filtereds(a.Namespace).Get(context.Background(), instanceID, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		logger.L().Debug("relevant SBOM manifest not found in storage", helpers.String("ID", instanceID))
		return domain.SBOM{}, nil
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to get relevant SBOM from apiserver", helpers.Error(err), helpers.String("ID", instanceID))
		return domain.SBOM{}, nil
	}
	// discard the manifest if it was created by an older version of the scanner
	if manifest.Spec.Metadata.Tool.Version != SBOMCreatorVersion {
		logger.L().Debug("discarding relevant SBOM with outdated scanner version", helpers.String("ID", instanceID), helpers.String("manifest scanner version", manifest.Spec.Metadata.Tool.Version), helpers.String("wanted scanner version", SBOMCreatorVersion))
		return domain.SBOM{}, nil
	}
	result := domain.SBOM{
		ID:                 instanceID,
		SBOMCreatorVersion: SBOMCreatorVersion,
		Content:            &manifest.Spec.SPDX,
		Labels:             manifest.Labels,
	}
	if status, ok := manifest.Annotations[domain.StatusKey]; ok {
		result.Status = status
	}
	logger.L().Debug("got relevant SBOM from storage", helpers.String("ID", instanceID))
	return result, nil
}

func (a *APIServerStore) StoreSBOM(ctx context.Context, sbom domain.SBOM) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreSBOM")
	defer span.End()
	if sbom.ID == "" {
		logger.L().Debug("skipping storing SBOM with empty ID")
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
	_, err = a.StorageClient.SBOMSPDXv2p3s(a.Namespace).Create(context.Background(), &manifest, metav1.CreateOptions{})
	switch {
	case errors.IsAlreadyExists(err):
		logger.L().Debug("SBOM manifest already exists in storage", helpers.String("ID", sbom.ID))
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to store SBOM into apiserver", helpers.Error(err), helpers.String("ID", sbom.ID))
	default:
		logger.L().Debug("stored SBOM in storage", helpers.String("ID", sbom.ID))
	}
	return nil
}
