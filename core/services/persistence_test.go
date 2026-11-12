package services

import (
	"context"
	"errors"
	"fmt"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	instanceidv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingResultRepository struct {
	ports.CVERepository
	manifestErr, summaryErr error
	onlyRelevant            bool
	summaryCalls            int
}

func (r *failingResultRepository) StoreCVE(ctx context.Context, cve domain.CVEManifest, relevant bool) error {
	if r.manifestErr != nil && (!r.onlyRelevant || relevant) {
		return r.manifestErr
	}
	return r.CVERepository.StoreCVE(ctx, cve, relevant)
}

func (r *failingResultRepository) StoreCVESummary(ctx context.Context, cve, cvep domain.CVEManifest, relevant bool) error {
	r.summaryCalls++
	if r.summaryErr != nil {
		return r.summaryErr
	}
	return r.CVERepository.StoreCVESummary(ctx, cve, cvep, relevant)
}

type persistencePlatform struct {
	recordingPlatform
	statuses []int
}

func (p *persistencePlatform) SendStatus(_ context.Context, step int) error {
	p.statuses = append(p.statuses, step)
	return nil
}

func TestScanService_PersistenceFailure(t *testing.T) {
	storageErr := errors.New("storage unavailable")
	uploadErr := errors.New("upload unavailable")
	for _, endpoint := range []string{"image", "registry"} {
		for _, phase := range []string{"fresh manifest", "fresh summary", "cached summary", "cached manifest"} {
			for _, uploadFails := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/uploadFails=%t", endpoint, phase, uploadFails), func(t *testing.T) {
					base := repositories.NewMemoryStorage(false, false)
					repo := &failingResultRepository{CVERepository: base}
					platform := &persistencePlatform{}
					if uploadFails {
						platform.submitErr = uploadErr
					}
					s, sbomVer, cveVer, dbVer, ctx := newScanCVETestService(t, platform, repo, fakeCVEScanner{})
					switch phase {
					case "fresh manifest":
						repo.manifestErr = storageErr
					case "fresh summary", "cached summary":
						repo.summaryErr = storageErr
					case "cached manifest":
						repo.manifestErr = storageErr
						platform.exceptions = exceptionPolicyForTest("CVE-A")
					}
					if phase == "cached summary" || phase == "cached manifest" {
						seedCachedCVEManifest(t, base, "imageSlug", sbomVer, cveVer, dbVer, ctx,
							&v1beta1.GrypeDocument{Matches: []v1beta1.Match{matchForTest("CVE-A"), matchForTest("CVE-B")}})
					}
					scan := s.ScanCVE
					if endpoint == "registry" {
						scan = s.ScanRegistry
					}
					err := scan(ctx)
					require.ErrorIs(t, err, storageErr)
					if uploadFails {
						require.ErrorIs(t, err, uploadErr, "neither failure may hide the other")
					}
					var scanErr *domain.ScanError
					require.ErrorAs(t, err, &scanErr)
					assert.Equal(t, ReasonResultStorageFailed, scanErr.Reason)
					assert.Len(t, platform.submitted, 1, "cloud upload must still be attempted")
					assert.NotContains(t, platform.statuses, domain.Success)
					assert.NotContains(t, platform.statuses, domain.Done)
					if repo.manifestErr != nil {
						assert.Zero(t, repo.summaryCalls, "do not publish a summary after its manifest failed")
					}
					// A later scan repairs the summary even when the successful manifest write is cached.
					repo.manifestErr, repo.summaryErr, platform.submitErr = nil, nil, nil
					require.NoError(t, scan(ctx))
					assert.Len(t, platform.submitted, 2)
					assert.NotEmpty(t, base.CVESummaries())
				})
			}
		}
	}
}

type persistenceRelevancy []ports.ContainerRelevancyScan

func (r persistenceRelevancy) GetContainerRelevancyScans(context.Context, string, string, bool) ([]ports.ContainerRelevancyScan, error) {
	return r, nil
}

func TestScanService_ScanCP_PersistenceFailureContinuesOtherContainers(t *testing.T) {
	for _, relevant := range []bool{false, true} {
		t.Run(fmt.Sprintf("relevant=%t", relevant), func(t *testing.T) {
			storageErr := errors.New("manifest write failed")
			repo := &failingResultRepository{
				CVERepository: repositories.NewMemoryStorage(false, false), manifestErr: storageErr, onlyRelevant: relevant,
			}
			platform := &persistencePlatform{}
			s, _, _, _, ctx := newScanCVETestService(t, platform, repo, fakeCVEScanner{})
			var scans persistenceRelevancy
			for _, container := range []string{"first", "second"} {
				id, err := instanceidv1.GenerateInstanceIDFromString("apiVersion-apps/v1/namespace-test/kind-Deployment/name-app/containerName-" + container)
				require.NoError(t, err)
				scans = append(scans, ports.ContainerRelevancyScan{
					ImageTag: "registry.test/app:1", ImageID: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
					InstanceID: id, ContainerName: container, Wlid: "wlid://cluster-test/namespace-test/deployment-app",
					RelevantFiles: mapset.NewSet[string](), Labels: map[string]string{},
				})
			}
			s.relevancyProvider = scans
			err := s.ScanCP(ctx)
			require.ErrorIs(t, err, storageErr)
			var scanErr *domain.ScanError
			require.ErrorAs(t, err, &scanErr)
			assert.Equal(t, ReasonResultStorageFailed, scanErr.Reason)
			assert.Len(t, platform.submitted, 2, "a failed write must not prevent either cloud upload")
			if !relevant {
				assert.Zero(t, repo.summaryCalls)
			}
		})
	}
}
