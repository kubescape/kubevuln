package services

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/armosec/armoapi-go/scanfailure"
	mapset "github.com/deckarep/golang-set/v2"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// scanHostCP consumes node-agent inventory independently of image SBOM creation
// and cache policy. A new request always scans the snapshot read in this attempt.
func (s *ScanService) scanHostCP(ctx context.Context, parent domain.ScanCommand, scan ports.ContainerRelevancyScan) error {
	instanceSlug, err := scan.InstanceID.GetSlug(false)
	if err != nil {
		return fmt.Errorf("getting host instance slug: %w", err)
	}
	workload := domain.ScanCommand{Wlid: scan.Wlid, ContainerName: scan.ContainerName, InstanceID: instanceSlug,
		JobID: parent.JobID, ParentJobID: parent.ParentJobID, Args: parent.Args, Session: parent.Session}
	ctx = enrichContext(ctx, workload, s.Version())
	scanID := ctx.Value(domain.ScanIDKey{})
	domain.RegisterHostInventoryFailureReporter(ctx, func(reportCtx context.Context, err error) {
		reportCtx = context.WithValue(reportCtx, domain.WorkloadKey{}, workload)
		reportCtx = context.WithValue(reportCtx, domain.ScanIDKey{}, scanID)
		_ = s.hostScanFailure(reportCtx, scanfailure.ScanFailureSBOMGeneration, scanfailure.ReasonUnexpected, err)
	})
	failInventory := func(err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, domain.ErrHostInventoryPending) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if acceptErr := domain.AcceptHostInventoryFailure(ctx); acceptErr != nil {
			return acceptErr
		}
		return s.hostScanFailure(ctx, scanfailure.ScanFailureSBOMGeneration, scanfailure.ReasonUnexpected, err)
	}
	repository, ok := s.sbomRepository.(ports.HostSBOMRepository)
	if !s.storage || !ok {
		return failInventory(fmt.Errorf("%w: host inventory storage is not available", domain.ErrHostInventoryUnavailable))
	}
	domain.UpdateScanPhase(ctx, "host_inventory_lookup")
	sbom, err := repository.GetHostSBOM(ctx, scan.HostNodeName)
	if err != nil {
		return failInventory(err)
	}
	if sbom.Content == nil || sbom.Content.SyftSource.Type != "directory" || sbom.Name == "" {
		return failInventory(fmt.Errorf("%w: invalid host inventory snapshot", domain.ErrHostInventoryUnavailable))
	}
	// Scanners and storage adapters add metadata. Isolate their mutations even if
	// another HostSBOMRepository implementation returns a shared snapshot.
	sbom = cloneHostSBOM(sbom)
	if sbom.Labels == nil {
		sbom.Labels = make(map[string]string)
	}
	if sbom.Annotations == nil {
		sbom.Annotations = make(map[string]string)
	}
	sbom.Labels[helpersv1.ArtifactTypeMetadataKey] = helpersv1.HostArtifactType
	sbom.Annotations[helpersv1.ToolVersionMetadataKey] = sbom.SBOMCreatorVersion
	sbom.Annotations[domain.HostInventoryToolNameAnnotationKey] = sbom.SBOMCreatorName
	sbom.Annotations[helpersv1.WlidMetadataKey] = scan.Wlid
	sbom.Annotations[helpersv1.ContainerNameMetadataKey] = scan.ContainerName
	filtered, err := filterHostSBOM(sbom, scan)
	if err != nil {
		return failInventory(fmt.Errorf("filtering host inventory: %w", err))
	}
	if filtered.Name == sbom.Name {
		return failInventory(fmt.Errorf("%w: host and CP result identities collide", domain.ErrHostInventoryUnavailable))
	}
	// The controller atomically arbitrates readiness versus timeout. No scan or
	// publication is allowed until acceptance succeeds for this attempt.
	if err := domain.AcceptHostInventory(ctx); err != nil {
		return err
	}
	domain.UpdateScanPhase(ctx, "cve_matching")
	cve, err := s.cveScanner.ScanSBOM(ctx, sbom)
	if err != nil {
		return s.hostScanFailure(ctx, scanfailure.ScanFailureCVE, scanfailure.ReasonCVEMatchingFailed, err)
	}
	cvep, err := s.cveScanner.ScanSBOM(ctx, filtered)
	if err != nil {
		return s.hostScanFailure(ctx, scanfailure.ScanFailureCVE, scanfailure.ReasonCVEMatchingFailed, err)
	}
	setHostCVEIdentity(&cve, sbom, scan.Wlid)
	setHostCVEIdentity(&cvep, filtered, scan.Wlid)
	stored, _ := s.applyExceptionsToManifest(ctx, cve)
	storedRelevant, _ := s.applyExceptionsToManifest(ctx, cvep)
	domain.UpdateScanPhase(ctx, "result_storage")
	if s.storeFilteredSbom {
		if err := s.sbomRepository.StoreSBOM(ctx, filtered, true); err != nil {
			return s.hostScanFailure(ctx, scanfailure.ScanFailureBackendPost, scanfailure.ReasonSBOMStorageFailed, err)
		}
	}
	if err := s.cveRepository.StoreCVE(ctx, stored, false); err != nil {
		return s.hostScanFailure(ctx, scanfailure.ScanFailureBackendPost, scanfailure.ReasonResultUploadFailed, err)
	}
	if err := s.cveRepository.StoreCVE(ctx, storedRelevant, true); err != nil {
		return s.hostScanFailure(ctx, scanfailure.ScanFailureBackendPost, scanfailure.ReasonResultUploadFailed, err)
	}
	if err := s.cveRepository.StoreCVESummary(ctx, stored, storedRelevant, true); err != nil {
		return s.hostScanFailure(ctx, scanfailure.ScanFailureBackendPost, scanfailure.ReasonResultUploadFailed, err)
	}
	// VEX currently represents image targets only; directory hosts retain the
	// existing directory limitation instead of manufacturing image metadata.
	domain.UpdateScanPhase(ctx, "result_upload")
	if err := s.platform.SubmitCVE(ctx, cve, cvep); err != nil {
		return s.hostScanFailure(ctx, scanfailure.ScanFailureBackendPost, scanfailure.ReasonResultUploadFailed, err)
	}
	return nil
}

func (s *ScanService) hostScanFailure(ctx context.Context, failureCase scanfailure.ScanFailureCase, reason string, err error) error {
	_ = s.platform.ReportScanFailure(ctx, failureCase, reason, err)
	return &domain.ScanError{Reason: reason, Err: err}
}

func setHostCVEIdentity(cve *domain.CVEManifest, sbom domain.SBOM, wlid string) {
	cve.Name, cve.Wlid = sbom.Name, wlid
	cve.SBOMCreatorName, cve.SBOMCreatorVersion = sbom.SBOMCreatorName, sbom.SBOMCreatorVersion
	cve.Labels = maps.Clone(cve.Labels)
	if cve.Labels == nil {
		cve.Labels = make(map[string]string)
	}
	maps.Copy(cve.Labels, sbom.Labels)
	cve.Labels[helpersv1.ArtifactTypeMetadataKey] = helpersv1.HostArtifactType
	cve.Annotations = maps.Clone(cve.Annotations)
	if cve.Annotations == nil {
		cve.Annotations = make(map[string]string)
	}
	maps.Copy(cve.Annotations, sbom.Annotations)
}

func cloneHostSBOM(sbom domain.SBOM) domain.SBOM {
	sbom.Annotations = maps.Clone(sbom.Annotations)
	sbom.Labels = maps.Clone(sbom.Labels)
	if sbom.Content != nil {
		wrapper := v1beta1.SBOMSyft{Spec: v1beta1.SBOMSyftSpec{Syft: *sbom.Content}}
		sbom.Content = &wrapper.DeepCopy().Spec.Syft
	}
	return sbom
}

func filterHostSBOM(sbom domain.SBOM, scan ports.ContainerRelevancyScan) (domain.SBOM, error) {
	normalized := cloneHostSBOM(sbom)
	paths := mapset.NewSet[string]()
	for _, p := range scan.RelevantFiles.ToSlice() {
		p, err := normalizeHostPath(p)
		if err != nil {
			return domain.SBOM{}, err
		}
		paths.Add(p)
	}
	// Only comparison coordinates are normalized. Restore original file records
	// afterward, preserving IDs, paths and graph relationships on the output.
	originals := make(map[string]v1beta1.SyftFile, len(normalized.Content.Files))
	for i := range normalized.Content.Files {
		f := &normalized.Content.Files[i]
		originals[f.ID] = *f
		p, err := normalizeHostPath(f.Location.RealPath)
		if err != nil {
			return domain.SBOM{}, err
		}
		f.Location.RealPath = p
	}
	labels := maps.Clone(scan.Labels)
	if labels == nil {
		labels = make(map[string]string)
	}
	// Inventory ownership was validated by the reader and must take precedence
	// over profile labels on every derived host result.
	maps.Copy(labels, sbom.Labels)
	filtered, err := filterSBOM(normalized, scan.InstanceID, scan.Wlid, paths, labels, scan.Completion)
	if err != nil {
		return domain.SBOM{}, err
	}
	filtered.Labels[helpersv1.ArtifactTypeMetadataKey] = helpersv1.HostArtifactType
	profilePaths := paths.ToSlice()
	slices.Sort(profilePaths)
	filtered.Annotations[domain.HostProfilePathsHashAnnotationKey] = fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(profilePaths, "\x00"))))
	for _, key := range []string{domain.HostInventoryUIDAnnotationKey, domain.HostInventoryResourceVersionAnnotationKey, domain.HostInventoryToolNameAnnotationKey} {
		filtered.Annotations[key] = sbom.Annotations[key]
	}
	for i, f := range filtered.Content.Files {
		filtered.Content.Files[i] = originals[f.ID]
	}
	return filtered, nil
}

// normalizeHostPath uses POSIX path segments without resolving filesystem links
// or interpreting a mount root such as /host. Placeholders remain literal.
func normalizeHostPath(value string) (string, error) {
	invalid := func() (string, error) { return "", fmt.Errorf("invalid host path %q", value) }
	if value == "" || strings.ContainsRune(value, '\x00') || strings.HasPrefix(value, "//") {
		return invalid()
	}
	var segments []string
	parts := strings.Split(value, "/")
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(segments) == 0 {
				return invalid()
			}
			// Collapsing a placeholder can change how many real segments are matched.
			if strings.ContainsAny(value, "*⋯") {
				return invalid()
			}
			segments = segments[:len(segments)-1]
		default:
			segments = append(segments, part)
		}
	}
	return "/" + strings.Join(segments, "/"), nil
}
