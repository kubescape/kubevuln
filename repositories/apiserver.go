package repositories

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"

	serrors "errors"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	"github.com/openvex/go-vex/pkg/vex"
	"go.opentelemetry.io/otel"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

const (
	vulnerabilityManifestSummaryKindPlural string = "vulnerabilitymanifests"
	vulnSummaryContNameFormat              string = "%s-%s-%s" // "<kind>-<name>-<container-name>"
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

	config := k8sinterface.GetK8sConfig()
	if config == nil {
		return nil, fmt.Errorf("failed to get k8s config")
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
	// TODO: also check SBOMCreatorVersion ? - we should, but we don't have the version in the manifest
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
func (a *APIServerStore) GetCVESummary(ctx context.Context) (*v1beta1.VulnerabilityManifestSummary, error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetCVESummary")
	defer span.End()
	name, err := GetCVESummaryK8sResourceName(ctx)
	if err != nil {
		return nil, err
	}
	if name == "" {
		logger.L().Debug("empty name provided, skipping summary CVE retrieval")
		return nil, nil
	}
	manifest, err := a.StorageClient.VulnerabilityManifestSummaries(a.Namespace).Get(context.Background(), name, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		logger.L().Debug("summary CVE manifest not found in storage",
			helpers.String("name", name))
		return nil, nil
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to get summary CVE manifest from apiserver", helpers.Error(err),
			helpers.String("name", name))
		return nil, nil
	}

	logger.L().Debug("got summary CVE manifest from storage",
		helpers.String("name", name))
	return manifest, nil
}

func (a *APIServerStore) StoreCVE(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error {
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
		cve.Labels[helpersv1.ContextMetadataKey] = helpersv1.ContextMetadataKeyFiltered
	} else {
		cve.Labels[helpersv1.ContextMetadataKey] = helpersv1.ContextMetadataKeyNonFiltered
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

func parseVulnerabilitiesComponents(cve domain.CVEManifest, cvep domain.CVEManifest, namespace string, withRelevancy bool) v1beta1.VulnerabilitiesComponents {
	vulComp := v1beta1.VulnerabilitiesComponents{}

	if withRelevancy {
		vulComp.WorkloadVulnerabilitiesObj.Name = cvep.Name
		vulComp.WorkloadVulnerabilitiesObj.Kind = vulnerabilityManifestSummaryKindPlural
		vulComp.WorkloadVulnerabilitiesObj.Namespace = namespace
	}
	vulComp.ImageVulnerabilitiesObj.Name = cve.Name
	vulComp.ImageVulnerabilitiesObj.Kind = vulnerabilityManifestSummaryKindPlural
	vulComp.ImageVulnerabilitiesObj.Namespace = namespace

	return vulComp
}

func parseSeverities(cve domain.CVEManifest, cvep domain.CVEManifest, withRelevancy bool) v1beta1.SeveritySummary {
	critical := 0
	criticalRelevant := 0
	high := 0
	highRelevant := 0
	medium := 0
	mediumRelevant := 0
	low := 0
	lowRelevant := 0
	negligible := 0
	negligibleRelevant := 0
	unknown := 0
	unknownRelevant := 0

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
	if withRelevancy {
		for i := range cvep.Content.Matches {
			switch cvep.Content.Matches[i].Vulnerability.Severity {
			case domain.CriticalSeverity:
				criticalRelevant += 1
			case domain.HighSeverity:
				highRelevant += 1
			case domain.MediumSeverity:
				mediumRelevant += 1
			case domain.LowSeverity:
				lowRelevant += 1
			case domain.NegligibleSeverity:
				negligibleRelevant += 1
			case domain.UnknownSeverity:
				unknownRelevant += 1
			}
		}
	}

	return v1beta1.SeveritySummary{
		Critical:   v1beta1.VulnerabilityCounters{All: critical, Relevant: criticalRelevant},
		High:       v1beta1.VulnerabilityCounters{All: high, Relevant: highRelevant},
		Medium:     v1beta1.VulnerabilityCounters{All: medium, Relevant: mediumRelevant},
		Low:        v1beta1.VulnerabilityCounters{All: low, Relevant: lowRelevant},
		Negligible: v1beta1.VulnerabilityCounters{All: negligible, Relevant: negligibleRelevant},
		Unknown:    v1beta1.VulnerabilityCounters{All: unknown, Relevant: unknownRelevant},
	}
}

func enrichSummaryManifestObjectAnnotations(ctx context.Context, annotations map[string]string) (map[string]string, error) {
	if annotations == nil {
		annotations = make(map[string]string)
	}
	enrichedAnnotations := annotations

	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return nil, domain.ErrCastingWorkload
	}
	enrichedAnnotations[helpersv1.WlidMetadataKey] = workload.Wlid
	enrichedAnnotations[helpersv1.ContainerNameMetadataKey] = workload.ContainerName

	return enrichedAnnotations, nil
}

func enrichSummaryManifestObjectLabels(ctx context.Context, labels map[string]string, withRelevancy bool) (map[string]string, error) {
	if labels == nil {
		labels = make(map[string]string)
	}
	if withRelevancy {
		labels[helpersv1.ContextMetadataKey] = helpersv1.ContextMetadataKeyFiltered
	} else {
		labels[helpersv1.ContextMetadataKey] = helpersv1.ContextMetadataKeyNonFiltered
	}
	enrichedLabels := labels

	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return nil, domain.ErrCastingWorkload
	}

	workloadKind := wlid.GetKindFromWlid(workload.Wlid)
	groupVersionScheme, err := k8sinterface.GetGroupVersionResource(workloadKind)
	if err != nil {
		return nil, err
	}

	enrichedLabels[helpersv1.ApiGroupMetadataKey] = groupVersionScheme.Group
	enrichedLabels[helpersv1.ApiVersionMetadataKey] = groupVersionScheme.Version
	enrichedLabels[helpersv1.KindMetadataKey] = strings.ToLower(workloadKind)
	enrichedLabels[helpersv1.NameMetadataKey] = wlid.GetNameFromWlid(workload.Wlid)
	enrichedLabels[helpersv1.NamespaceMetadataKey] = wlid.GetNamespaceFromWlid(workload.Wlid)
	enrichedLabels[helpersv1.ContainerNameMetadataKey] = workload.ContainerName

	return enrichedLabels, nil
}

func GetCVESummaryK8sResourceName(ctx context.Context) (string, error) {
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return "", domain.ErrCastingWorkload
	}
	kind := strings.ToLower(wlid.GetKindFromWlid(workload.Wlid))
	name := strings.ToLower(wlid.GetNameFromWlid(workload.Wlid))
	contName := strings.ToLower(workload.ContainerName)

	return fmt.Sprintf(vulnSummaryContNameFormat, kind, name, contName), nil
}

func GetCVESummaryK8sResourceNamespace(ctx context.Context) (string, error) {
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return "", domain.ErrCastingWorkload
	}

	return wlid.GetNamespaceFromWlid(workload.Wlid), nil
}

func (a *APIServerStore) StoreCVESummary(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest, withRelevancy bool) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreCVESummary")
	defer span.End()

	if cve.Name == "" {
		logger.L().Debug("skipping storing CVE manifest with empty name",
			helpers.String("relevant", strconv.FormatBool(withRelevancy)))
		return nil
	}

	annotations, err := enrichSummaryManifestObjectAnnotations(ctx, cve.Annotations)
	if err != nil {
		return err
	}
	labels, err := enrichSummaryManifestObjectLabels(ctx, cve.Labels, withRelevancy)
	if err != nil {
		return err
	}
	summaryK8sResourceName, err := GetCVESummaryK8sResourceName(ctx)
	if err != nil {
		return err
	}
	workloadNamespace, err := GetCVESummaryK8sResourceNamespace(ctx)
	if err != nil {
		return err
	}

	manifest := v1beta1.VulnerabilityManifestSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name:        summaryK8sResourceName,
			Annotations: annotations,
			Labels:      labels,
		},
		Spec: v1beta1.VulnerabilityManifestSummarySpec{
			Severities:      parseSeverities(cve, cvep, withRelevancy),
			Vulnerabilities: parseVulnerabilitiesComponents(cve, cvep, workloadNamespace, withRelevancy),
		},
	}
	_, err = a.StorageClient.VulnerabilityManifestSummaries(workloadNamespace).Create(context.Background(), &manifest, metav1.CreateOptions{})
	switch {
	case errors.IsAlreadyExists(err):
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			// retrieve the latest version before attempting update
			// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
			result, getErr := a.StorageClient.VulnerabilityManifestSummaries(workloadNamespace).Get(context.Background(), manifest.Name, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			result.ResourceVersion = ""
			result.UID = ""

			// update the vulnerability manifest
			result.Annotations = manifest.Annotations
			result.Labels = manifest.Labels
			result.Spec = manifest.Spec
			// try to send the updated vulnerability manifest
			_, updateErr := a.StorageClient.VulnerabilityManifestSummaries(workloadNamespace).Update(context.Background(), result, metav1.UpdateOptions{})
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
			helpers.String("name", manifest.Name),
			helpers.String("relevant", strconv.FormatBool(withRelevancy)))
	}
	return nil
}

func (a *APIServerStore) StoreVEX(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest, withRelevancy bool) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreVEX")
	defer span.End()

	if cve.Name == "" {
		logger.L().Debug("skipping storing VEX with empty name")
		return nil
	}

	// Check if VEX already exists
	// If it does, update it
	// If it doesn't, create it
	vexContainer, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(context.Background(), cve.Name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			// Create VEX
			err = a.createVEX(ctx, cve, cvep)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		// Update VEX
		err = a.updateVEX(ctx, cve, cvep, vexContainer)
		if err != nil {
			return err
		}
	}

	return nil

}

func createProductStructForImageAndPackage(imagePullable string, packagePURL string) (*v1beta1.Product, error) {
	imagePullable = strings.TrimPrefix(imagePullable, "docker://")
	imageComponents := strings.Split(imagePullable, "/")
	imageName := imageComponents[len(imageComponents)-1]
	imageRepo := strings.Join(imageComponents[:len(imageComponents)-1], "/")
	// pkg:oci/adservice@sha256%3A45fb8ed886902c0c49e044b1f8870fad61c1022fa23c4943098302a8f1c5b75f?repository_url=gcr.io/google-samples/microservices-demo
	imageField := fmt.Sprintf("pkg:oci/%s?repository_url=%s", url.PathEscape(imageName), url.PathEscape(imageRepo))
	product := v1beta1.Product{
		Component: v1beta1.Component{
			ID: imageField,
		},
	}
	product.Subcomponents = append(product.Subcomponents, v1beta1.Subcomponent{
		Component: v1beta1.Component{
			ID: packagePURL,
		},
	})
	return &product, nil
}

func markRelevantVulnerabilitiesAsAffectedInVex(vexDoc *v1beta1.VEX, cvep *domain.CVEManifest) error {
	// Now change the status of the filtered vulnerabilities to "Affected"
	for _, v := range cvep.Content.Matches {
		for i, s := range vexDoc.Statements {
			if s.Vulnerability.ID == v.Vulnerability.ID {
				foundProduct := false
				for _, p := range s.Products {
					for _, sc := range p.Subcomponents {
						if sc.ID == v.Artifact.PURL {
							vexDoc.Statements[i].Status = v1beta1.Status(vex.StatusAffected)
							vexDoc.Statements[i].Justification = ""
							vexDoc.Statements[i].ImpactStatement = "Vulnerable component is loaded into the memory"
							foundProduct = true
						}
						if foundProduct {
							break
						}
					}
					if foundProduct {
						break
					}
				}
			}
		}
	}
	return nil
}

func (a *APIServerStore) createVEX(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.createVEX")
	defer span.End()

	imagePullable := cve.Annotations[helpersv1.ImageIDMetadataKey]

	// Timestamp
	timestamp := time.Now().Format(time.RFC3339)

	// Calculate VEX
	vexDoc := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Context:     "https://openvex.dev/ns/v0.2.0",
			Author:      "kubescape.io",
			AuthorRole:  "smart vulnerability scanner :-)",
			Timestamp:   timestamp,
			LastUpdated: timestamp,
			Version:     0,
			Tooling:     "kubescape-vulnerability-analyzer",
		},
	}

	// Loop over the Vulnerability struct and add each vulnerability to the VEX document
	for _, v := range cve.Content.Matches {
		var aliases []string
		for _, alias := range v.RelatedVulnerabilities {
			aliases = append(aliases, string(alias.ID))
		}

		product, err := createProductStructForImageAndPackage(imagePullable, v.Artifact.PURL)

		if err != nil {
			return err
		}

		vexDoc.Statements = append(vexDoc.Statements, v1beta1.Statement{
			Vulnerability: v1beta1.VexVulnerability{
				ID:          v.Vulnerability.ID,
				Name:        v.Vulnerability.DataSource,
				Description: v.Vulnerability.Description,
				Aliases:     aliases,
			},

			Products: []v1beta1.Product{
				*product,
			},

			Status:          v1beta1.Status(vex.StatusNotAffected),
			Justification:   v1beta1.Justification(vex.VulnerableCodeNotPresent),
			ImpactStatement: "Vulnerable component is not loaded into the memory",
		})
	}

	// Now change the status of the filtered vulnerabilities to "Affected"
	err := markRelevantVulnerabilitiesAsAffectedInVex(&vexDoc, &cvep)
	if err != nil {
		return err
	}

	calculatedId, err := calculateVexCanonicalHash(vexDoc)
	if err != nil {
		return err
	}

	vexDoc.Metadata.ID = calculatedId

	// Create the VEX container
	vexContainer := v1beta1.OpenVulnerabilityExchangeContainer{
		ObjectMeta: metav1.ObjectMeta{
			Name:        cve.Name,
			Labels:      cve.Labels,
			Annotations: cve.Annotations,
		},
		Spec: vexDoc,
	}

	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Create(context.Background(), &vexContainer, metav1.CreateOptions{})

	return err
}

func (a *APIServerStore) updateVEX(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest, vexContainer *v1beta1.OpenVulnerabilityExchangeContainer) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.updateVEX")
	defer span.End()

	imagePullable := cve.Annotations[helpersv1.ImageIDMetadataKey]

	// Extend the VEX document with vulnerability data from full vulnerability manifest
	vexDoc := vexContainer.Spec
	for _, v := range cve.Content.Matches {
		found := false
		for _, s := range vexDoc.Statements {
			if s.Vulnerability.ID == v.Vulnerability.ID && v.Artifact.PURL == s.Products[0].Subcomponents[0].ID {
				found = true
				continue
			}
		}
		if !found {
			// Add the vulnerability to the VEX document
			var aliases []string
			for _, alias := range v.RelatedVulnerabilities {
				aliases = append(aliases, string(alias.ID))
			}

			product, err := createProductStructForImageAndPackage(imagePullable, v.Artifact.PURL)
			if err != nil {
				return err
			}

			vexDoc.Statements = append(vexDoc.Statements, v1beta1.Statement{
				Vulnerability: v1beta1.VexVulnerability{
					ID:          v.Vulnerability.DataSource,
					Name:        v.Vulnerability.ID,
					Description: v.Vulnerability.Description,
					Aliases:     aliases,
				},

				Products: []v1beta1.Product{
					*product,
				},

				Status:          v1beta1.Status(vex.StatusNotAffected),
				Justification:   v1beta1.Justification(vex.VulnerableCodeNotPresent),
				ImpactStatement: "Vulnerable component is not loaded into the memory",
			})
		}
	}

	// Now change the status of the filtered vulnerabilities to "Affected"
	err := markRelevantVulnerabilitiesAsAffectedInVex(&vexDoc, &cvep)
	if err != nil {
		return err
	}

	// Update the VEX document metadata
	vexDoc.Metadata.LastUpdated = time.Now().Format(time.RFC3339)
	vexDoc.Metadata.Version += 1

	calculatedId, err := calculateVexCanonicalHash(vexDoc)
	if err != nil {
		return err
	}

	vexDoc.Metadata.ID = calculatedId

	// Update the VEX container
	vexContainer.Spec = vexDoc
	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Update(context.Background(), vexContainer, metav1.UpdateOptions{})

	return err
}

func calculateVexCanonicalHash(vexDoc v1beta1.VEX) (string, error) {
	// Here's the algo:

	ts, err := time.Parse(time.RFC3339, vexDoc.Timestamp)
	if err != nil {
		return "", err
	}
	cString := fmt.Sprintf("%d", ts.Unix())

	cString += fmt.Sprintf(":%d", vexDoc.Version)

	cString += fmt.Sprintf(":%s", vexDoc.Author)

	stmts := vexDoc.Statements
	sortVexStatements(stmts, ts)

	//nolint:gocritic
	for _, s := range stmts {
		// 5a. Vulnerability
		cString += cstringFromVulnerability(s.Vulnerability)
		// 5b. Status + Justification
		cString += fmt.Sprintf(":%s:%s", s.Status, s.Justification)
		// 5c. Statement time, in unixtime. If it exists, if not the doc's
		if s.Timestamp != "" {
			ts, _ := time.Parse(time.RFC3339, s.Timestamp)
			cString += fmt.Sprintf(":%d", ts.Unix())
		} else {
			ts, _ := time.Parse(time.RFC3339, vexDoc.Timestamp)
			cString += fmt.Sprintf(":%d", ts.Unix())
		}
		// 5d. Sorted product strings
		prods := []string{}
		for _, p := range s.Products {
			prodString := cstringFromComponent(p.Component)
			if p.Subcomponents != nil && len(p.Subcomponents) > 0 {
				for _, sc := range p.Subcomponents {
					prodString += cstringFromComponent(sc.Component)
				}
			}
			prods = append(prods, prodString)
		}
		sort.Strings(prods)
		cString += fmt.Sprintf(":%s", strings.Join(prods, ":"))
	}

	h := sha256.New()
	if _, err := h.Write([]byte(cString)); err != nil {
		return "", fmt.Errorf("hashing canonicalization string: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func sortVexStatements(stmts []v1beta1.Statement, documentTimestamp time.Time) {
	sort.SliceStable(stmts, func(i, j int) bool {
		// TODO: Add methods for aliases
		vulnComparison := strings.Compare(string(stmts[i].Vulnerability.Name), string(stmts[j].Vulnerability.Name))
		if vulnComparison != 0 {
			// i.e. different vulnerabilities; sort by string comparison
			return vulnComparison < 0
		}

		// i.e. the same vulnerability; sort statements by timestamp

		iTime, _ := time.Parse(time.RFC3339, stmts[i].Timestamp)
		if iTime.IsZero() {
			iTime = documentTimestamp
		}

		jTime, _ := time.Parse(time.RFC3339, stmts[j].Timestamp)
		if jTime.IsZero() {
			jTime = documentTimestamp
		}

		return iTime.Before(jTime)
	})
}

func cstringFromVulnerability(v v1beta1.VexVulnerability) string {
	cString := fmt.Sprintf(":%s:%s", v.ID, v.Name)
	list := []string{}
	for i := range v.Aliases {
		list = append(list, string(v.Aliases[i]))
	}
	sort.Strings(list)
	cString += strings.Join(list, ":")
	return cString
}

func cstringFromComponent(c v1beta1.Component) string {
	s := fmt.Sprintf(":%s", c.ID)

	for algo, val := range c.Hashes {
		s += fmt.Sprintf(":%s@%s", algo, val)
	}

	for t, id := range c.Identifiers {
		s += fmt.Sprintf(":%s@%s", t, id)
	}

	return s
}

func (a *APIServerStore) GetSBOM(ctx context.Context, name, SBOMCreatorVersion string) (domain.SBOM, error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetSBOM")
	defer span.End()
	if name == "" {
		logger.L().Debug("empty name provided, skipping SBOM retrieval")
		return domain.SBOM{}, nil
	}
	manifest, err := a.StorageClient.SBOMSyfts(a.Namespace).Get(context.Background(), name, metav1.GetOptions{})
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
		Content:            &manifest.Spec.Syft,
	}
	if status, ok := manifest.Annotations[helpersv1.StatusMetadataKey]; ok {
		result.Status = status
	}
	logger.L().Debug("got SBOM from storage",
		helpers.String("name", name))
	return result, nil
}

func validateSBOMp(manifest *v1beta1.SBOMSyftFiltered, sbomCreatorVersion string) error {
	if status, ok := manifest.Annotations[helpersv1.StatusMetadataKey]; ok && status == helpersv1.Incomplete {
		return domain.ErrIncompleteSBOM
	}
	if manifest.Spec.Metadata.Tool.Version == "v0.101.1" || manifest.Spec.Metadata.Tool.Version == "v0.101.1-hotfix" { // hard coded version. We have a specific workaround for this version
		return domain.ErrSBOMWithPartialArtifacts
	}
	if manifest.Spec.Metadata.Tool.Version != sbomCreatorVersion {
		return domain.ErrOutdatedSBOM
	}

	return nil
}

func (a *APIServerStore) GetSBOMp(ctx context.Context, name, sbomCreatorVersion string) (domain.SBOM, error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetSBOMp")
	defer span.End()
	if name == "" {
		logger.L().Debug("empty name provided, skipping relevant SBOM retrieval")
		return domain.SBOM{}, nil
	}
	manifest, err := a.StorageClient.SBOMSyftFiltereds(a.Namespace).Get(context.Background(), name, metav1.GetOptions{})
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
	vErr := validateSBOMp(manifest, sbomCreatorVersion)
	if vErr != nil {
		if !serrors.Is(vErr, domain.ErrSBOMWithPartialArtifacts) {
			logger.L().Debug("discarding relevant SBOM", helpers.Error(vErr),
				helpers.String("name", name))
			return domain.SBOM{}, nil
		}
	}
	result := domain.SBOM{
		Name:               name,
		Annotations:        manifest.Annotations,
		Labels:             manifest.Labels,
		SBOMCreatorVersion: sbomCreatorVersion,
		Content:            &manifest.Spec.Syft,
	}
	if status, ok := manifest.Annotations[helpersv1.StatusMetadataKey]; ok {
		result.Status = status
	}
	logger.L().Debug("got relevant SBOM from storage",
		helpers.String("name", name))
	return result, vErr
}

func (a *APIServerStore) StoreSBOM(ctx context.Context, sbom domain.SBOM) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreSBOMWithContent")
	defer span.End()

	if sbom.Name == "" {
		logger.L().Debug("skipping storing SBOM with empty name")
		return nil
	}
	manifest := v1beta1.SBOMSyft{
		ObjectMeta: metav1.ObjectMeta{
			Name:        sbom.Name,
			Annotations: sbom.Annotations,
			Labels:      sbom.Labels,
		},
		Spec: v1beta1.SBOMSyftSpec{
			Metadata: v1beta1.SPDXMeta{
				Tool: v1beta1.ToolMeta{
					Name:    sbom.SBOMCreatorName,
					Version: sbom.SBOMCreatorVersion,
				},
				Report: v1beta1.ReportMeta{
					CreatedAt: metav1.Now().Rfc3339Copy(),
				},
			},
		},
		Status: v1beta1.SBOMSyftStatus{}, // TODO move timeout information here
	}

	if sbom.Content != nil {
		manifest.Spec.Syft = *sbom.Content
	}
	if manifest.Annotations == nil {
		manifest.Annotations = map[string]string{}
	}
	manifest.Annotations[helpersv1.StatusMetadataKey] = sbom.Status // for the moment stored as an annotation
	_, err := a.StorageClient.SBOMSyfts(a.Namespace).Create(context.Background(), &manifest, metav1.CreateOptions{})
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
