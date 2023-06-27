package repositories

import (
	"context"
	"strconv"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	v1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
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
	"k8s.io/client-go/util/retry"
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

func (a *APIServerStore) GetCVE(ctx context.Context, name, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (domain.CVEManifest, error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetCVE")
	defer span.End()
	if name == "" {
		logger.L().Debug("empty name provided, skipping CVE retrieval")
		return domain.CVEManifest{}, nil
	}
	manifest, err := a.StorageClient.VulnerabilityManifests(a.Namespace).Get(context.Background(), name, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		logger.L().Debug("CVE manifest not found in storage",
			helpers.String("name", name))
		return domain.CVEManifest{}, nil
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to get CVE manifest from apiserver", helpers.Error(err),
			helpers.String("name", name))
		return domain.CVEManifest{}, nil
	}
	// discard the manifest if it was created by an older version of the scanner
	// TODO: also check SBOMCreatorVersion ?
	if manifest.Spec.Metadata.Tool.Version != CVEScannerVersion || manifest.Spec.Metadata.Tool.DatabaseVersion != CVEDBVersion {
		logger.L().Debug("discarding CVE manifest with outdated scanner version",
			helpers.String("name", name),
			helpers.String("manifest scanner version", manifest.Spec.Metadata.Tool.Version),
			helpers.String("manifest DB version", manifest.Spec.Metadata.Tool.DatabaseVersion),
			helpers.String("wanted scanner version", CVEScannerVersion),
			helpers.String("wanted DB version", CVEDBVersion))
		return domain.CVEManifest{}, nil
	}
	logger.L().Debug("got CVE manifest from storage",
		helpers.String("name", name))
	return domain.CVEManifest{
		Name:               name,
		Annotations:        manifest.Annotations,
		Labels:             manifest.Labels,
		SBOMCreatorVersion: SBOMCreatorVersion,
		CVEScannerVersion:  CVEScannerVersion,
		CVEDBVersion:       CVEDBVersion,
		Content:            &manifest.Spec.Payload,
	}, nil
}

func (a *APIServerStore) storeCVEWithFullContent(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreCVEWithFullContent")
	defer span.End()

	if cve.Name == "" {
		logger.L().Debug("skipping storing CVE manifest with empty name",
			helpers.String("relevant", strconv.FormatBool(withRelevancy)))
		return nil
	}
	if cve.Labels == nil {
		cve.Labels = make(map[string]string)
	}

	if withRelevancy {
		cve.Labels[v1.ContextMetadataKey] = v1.ContextMetadataKeyFiltered
	} else {
		cve.Labels[v1.ContextMetadataKey] = v1.ContextMetadataKeyNonFiltered
	}

	manifest := v1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        cve.Name,
			Annotations: cve.Annotations,
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
		},
	}
	if cve.Content != nil {
		manifest.Spec.Payload = *cve.Content
	}
	_, err := a.StorageClient.VulnerabilityManifests(a.Namespace).Create(context.Background(), &manifest, metav1.CreateOptions{})
	switch {
	case errors.IsAlreadyExists(err):
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			// retrieve the latest version before attempting update
			// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
			result, getErr := a.StorageClient.VulnerabilityManifests(a.Namespace).Get(context.Background(), cve.Name, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			// update the vulnerability manifest
			result.Annotations = manifest.Annotations
			result.Labels = manifest.Labels
			result.Spec = manifest.Spec
			// try to send the updated vulnerability manifest
			_, updateErr := a.StorageClient.VulnerabilityManifests(a.Namespace).Update(context.Background(), result, metav1.UpdateOptions{})
			return updateErr
		})
		if retryErr != nil {
			logger.L().Ctx(ctx).Warning("failed to update CVE manifest in storage", helpers.Error(err),
				helpers.String("name", cve.Name),
				helpers.String("relevant", strconv.FormatBool(withRelevancy)))
		} else {
			logger.L().Debug("updated CVE manifest in storage",
				helpers.String("name", cve.Name),
				helpers.String("relevant", strconv.FormatBool(withRelevancy)))
		}
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to store CVE manifest in storage", helpers.Error(err),
			helpers.String("name", cve.Name),
			helpers.String("relevant", strconv.FormatBool(withRelevancy)))
	default:
		logger.L().Debug("stored CVE manifest in storage",
			helpers.String("name", cve.Name),
			helpers.String("relevant", strconv.FormatBool(withRelevancy)))
	}
	return nil
}

func parseSeverities(cve domain.CVEManifest) v1beta1.SeveritySummary {
	critical := 0
	high := 0
	medium := 0
	low := 0
	negligible := 0
	unknown := 0

	for i := range cve.Content.Matches {
		switch cve.Content.Matches[i].Vulnerability.Severity {
		case domain.CriticalSeverity:
			critical += 1
		case domain.HighSeverity:
			high += 1
		case domain.MediumSeverity:
			medium += 1
		case domain.LowSeverity:
			low += 1
		case domain.NegligibleSeverity:
			negligible += 1
		case domain.UnknownSeverity:
			unknown += 1
		}
	}

	return v1beta1.SeveritySummary{
		Critical:   v1beta1.VulnerabilityCounters{All: critical},
		High:       v1beta1.VulnerabilityCounters{All: high},
		Medium:     v1beta1.VulnerabilityCounters{All: medium},
		Low:        v1beta1.VulnerabilityCounters{All: low},
		Negligible: v1beta1.VulnerabilityCounters{All: negligible},
		Unknown:    v1beta1.VulnerabilityCounters{All: unknown},
	}
}

func (a *APIServerStore) storeCVESummary(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.storeCVESummary")
	defer span.End()

	if cve.Name == "" {
		logger.L().Debug("skipping storing CVE manifest with empty name",
			helpers.String("relevant", strconv.FormatBool(withRelevancy)))
		return nil
	}
	if cve.Labels == nil {
		cve.Labels = make(map[string]string)
	}

	if withRelevancy {
		cve.Labels[v1.ContextMetadataKey] = v1.ContextMetadataKeyFiltered
	} else {
		cve.Labels[v1.ContextMetadataKey] = v1.ContextMetadataKeyNonFiltered
	}

	manifest := v1beta1.VulnerabilityManifestSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name:        cve.Name,
			Annotations: cve.Annotations,
			Labels:      cve.Labels,
		},
		Spec: v1beta1.VulnerabilityManifestSummarySpec{
			Severities: parseSeverities(cve),
		},
	}
	_, err := a.StorageClient.VulnerabilityManifestSummaries(a.Namespace).Create(context.Background(), &manifest, metav1.CreateOptions{})
	switch {
	case errors.IsAlreadyExists(err):
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			// retrieve the latest version before attempting update
			// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
			result, getErr := a.StorageClient.VulnerabilityManifestSummaries(a.Namespace).Get(context.Background(), cve.Name, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			// update the vulnerability manifest
			result.Annotations = manifest.Annotations
			result.Labels = manifest.Labels
			result.Spec = manifest.Spec
			// try to send the updated vulnerability manifest
			_, updateErr := a.StorageClient.VulnerabilityManifestSummaries(a.Namespace).Update(context.Background(), result, metav1.UpdateOptions{})
			return updateErr
		})
		if retryErr != nil {
			logger.L().Ctx(ctx).Warning("failed to update CVE summary manifest in storage", helpers.Error(err),
				helpers.String("name", cve.Name),
				helpers.String("relevant", strconv.FormatBool(withRelevancy)))
		} else {
			logger.L().Debug("updated CVE summary manifest in storage",
				helpers.String("name", cve.Name),
				helpers.String("relevant", strconv.FormatBool(withRelevancy)))
		}
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to store CVE summary manifest in storage", helpers.Error(err),
			helpers.String("name", cve.Name),
			helpers.String("relevant", strconv.FormatBool(withRelevancy)))
	default:
		logger.L().Debug("stored CVE summary manifest in storage",
			helpers.String("name", cve.Name),
			helpers.String("relevant", strconv.FormatBool(withRelevancy)))
	}
	return nil
}

func (a *APIServerStore) StoreCVE(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error {
	innerCtx, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreCVE")
	defer span.End()

	err := a.storeCVEWithFullContent(innerCtx, cve, withRelevancy)
	if err != nil {
		return err
	}

	err = a.storeCVESummary(innerCtx, cve, withRelevancy)
	if err != nil {
		return err
	}

	return nil
}

func (a *APIServerStore) GetSBOM(ctx context.Context, name, SBOMCreatorVersion string) (domain.SBOM, error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetSBOM")
	defer span.End()
	if name == "" {
		logger.L().Debug("empty name provided, skipping SBOM retrieval")
		return domain.SBOM{}, nil
	}
	manifest, err := a.StorageClient.SBOMSPDXv2p3s(a.Namespace).Get(context.Background(), name, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		logger.L().Debug("SBOM manifest not found in storage",
			helpers.String("name", name))
		return domain.SBOM{}, nil
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to get SBOM from apiserver", helpers.Error(err),
			helpers.String("name", name))
		return domain.SBOM{}, nil
	}
	// discard the manifest if it was created by an older version of the scanner
	if manifest.Spec.Metadata.Tool.Version != SBOMCreatorVersion {
		logger.L().Debug("discarding SBOM with outdated scanner version",
			helpers.String("name", name),
			helpers.String("manifest scanner version", manifest.Spec.Metadata.Tool.Version),
			helpers.String("wanted scanner version", SBOMCreatorVersion))
		return domain.SBOM{}, nil
	}
	result := domain.SBOM{
		Name:               name,
		Annotations:        manifest.Annotations,
		Labels:             manifest.Labels,
		SBOMCreatorVersion: SBOMCreatorVersion,
		Content:            &manifest.Spec.SPDX,
	}
	if status, ok := manifest.Annotations[instanceidhandler.StatusMetadataKey]; ok {
		result.Status = status
	}
	logger.L().Debug("got SBOM from storage",
		helpers.String("name", name))
	return result, nil
}

func validateSBOMp(manifest *v1beta1.SBOMSPDXv2p3Filtered) error {
	if status, ok := manifest.Annotations[instanceidhandler.StatusMetadataKey]; ok && status == instanceidhandler.Incomplete {
		return domain.ErrIncompleteSBOM
	}
	return nil
}

func (a *APIServerStore) GetSBOMp(ctx context.Context, name, SBOMCreatorVersion string) (domain.SBOM, error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetSBOMp")
	defer span.End()
	if name == "" {
		logger.L().Debug("empty name provided, skipping relevant SBOM retrieval")
		return domain.SBOM{}, nil
	}
	manifest, err := a.StorageClient.SBOMSPDXv2p3Filtereds(a.Namespace).Get(context.Background(), name, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		logger.L().Debug("relevant SBOM manifest not found in storage",
			helpers.String("name", name))
		return domain.SBOM{}, nil
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to get relevant SBOM from apiserver", helpers.Error(err),
			helpers.String("name", name))
		return domain.SBOM{}, nil
	}
	// validate SBOMp manifest
	if err := validateSBOMp(manifest); err != nil {
		logger.L().Debug("discarding relevant SBOM", helpers.Error(err),
			helpers.String("name", name))
		return domain.SBOM{}, nil
	}
	result := domain.SBOM{
		Name:               name,
		Annotations:        manifest.Annotations,
		Labels:             manifest.Labels,
		SBOMCreatorVersion: SBOMCreatorVersion,
		Content:            &manifest.Spec.SPDX,
	}
	if status, ok := manifest.Annotations[instanceidhandler.StatusMetadataKey]; ok {
		result.Status = status
	}
	logger.L().Debug("got relevant SBOM from storage",
		helpers.String("name", name))
	return result, nil
}

func (a *APIServerStore) storeSBOMWithContent(ctx context.Context, sbom domain.SBOM) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreSBOMWithContent")
	defer span.End()

	if sbom.Name == "" {
		logger.L().Debug("skipping storing SBOM with empty name")
		return nil
	}
	manifest := v1beta1.SBOMSPDXv2p3{
		ObjectMeta: metav1.ObjectMeta{
			Name:        sbom.Name,
			Annotations: sbom.Annotations,
			Labels:      sbom.Labels,
		},
		Spec: v1beta1.SBOMSPDXv2p3Spec{
			Metadata: v1beta1.SPDXMeta{
				Tool: v1beta1.ToolMeta{
					Name:    sbom.SBOMCreatorName,
					Version: sbom.SBOMCreatorVersion,
				},
			},
		},
		Status: v1beta1.SBOMSPDXv2p3Status{}, // TODO move timeout information here
	}
	if sbom.Content != nil {
		manifest.Spec.SPDX = *sbom.Content
		created, err := time.Parse(time.RFC3339, sbom.Content.CreationInfo.Created)
		if err != nil {
			manifest.Spec.Metadata.Report.CreatedAt.Time = created
		}
	}
	if manifest.Annotations == nil {
		manifest.Annotations = map[string]string{}
	}
	manifest.Annotations[instanceidhandler.StatusMetadataKey] = sbom.Status // for the moment stored as an annotation
	_, err := a.StorageClient.SBOMSPDXv2p3s(a.Namespace).Create(context.Background(), &manifest, metav1.CreateOptions{})
	switch {
	case errors.IsAlreadyExists(err):
		logger.L().Debug("SBOM manifest already exists in storage",
			helpers.String("name", sbom.Name))
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to store SBOM into apiserver", helpers.Error(err),
			helpers.String("name", sbom.Name))
	default:
		logger.L().Debug("stored SBOM in storage",
			helpers.String("name", sbom.Name))
	}
	return nil
}

func (a *APIServerStore) storeSBOMWithoutContent(ctx context.Context, sbom domain.SBOM) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreSBOMWithoutContent")
	defer span.End()

	if sbom.Name == "" {
		logger.L().Debug("skipping storing SBOM with empty name")
		return nil
	}
	manifest := v1beta1.SBOMSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name:        sbom.Name,
			Annotations: sbom.Annotations,
			Labels:      sbom.Labels,
		},
		Spec:   v1beta1.SBOMSummarySpec{},
		Status: v1beta1.SBOMSPDXv2p3Status{}, // TODO move timeout information here
	}
	if manifest.Annotations == nil {
		manifest.Annotations = map[string]string{}
	}
	manifest.Annotations[instanceidhandler.StatusMetadataKey] = sbom.Status // for the moment stored as an annotation
	_, err := a.StorageClient.SBOMSummaries(a.Namespace).Create(context.Background(), &manifest, metav1.CreateOptions{})
	switch {
	case errors.IsAlreadyExists(err):
		logger.L().Debug("SBOM summary manifest already exists in storage",
			helpers.String("name", sbom.Name))
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to store SBOM summary into apiserver", helpers.Error(err),
			helpers.String("name", sbom.Name))
	default:
		logger.L().Debug("stored SBOM summary in storage",
			helpers.String("name", sbom.Name))
	}
	return nil
}

func (a *APIServerStore) StoreSBOM(ctx context.Context, sbom domain.SBOM) error {
	innerCtx, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreSBOM")
	defer span.End()

	err := a.storeSBOMWithContent(innerCtx, sbom)
	if err != nil {
		return err
	}

	err = a.storeSBOMWithoutContent(innerCtx, sbom)
	if err != nil {
		return err
	}

	return nil
}
