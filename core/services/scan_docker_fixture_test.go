//go:build dockerfixture

package services

import (
	"context"
	"errors"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/adapters"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanService_NginxTest(t *testing.T) {
	imageSlug := "docker.io-library-nginx-1.14.1-3dc228"
	slug := "replicaset-nginx-75f48cbc54-nginx-10dc-2a65"
	ctx := context.TODO()
	sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
	cveAdapter, terminate, err := v1.NewGrypeAdapterFixedDB()
	if errors.Is(err, v1.ErrDockerUnavailable) {
		t.Skipf("skipping: grype offline db container unavailable (container runtime not usable): %v", err)
	}
	require.NoError(t, err)
	defer terminate()
	storageCP := repositories.NewMemoryStorage(false, false)
	storageSBOM := repositories.NewMemoryStorage(false, false)
	storageCVE := repositories.NewMemoryStorage(false, false)
	platform := adapters.NewMockPlatform(false, nil)
	relevancyProvider := v1.NewContainerProfileAdapter(storageCP)
	s := NewScanService(sbomAdapter, storageSBOM, cveAdapter, storageCVE, platform, relevancyProvider, true, false, true, false, false)
	s.Ready(ctx)
	workload := domain.ScanCommand{
		Args: map[string]interface{}{
			domain.ArgsName:      "replicaset-nginx-75f48cbc54-nginx-714a-83bf",
			domain.ArgsNamespace: "default",
		},
		Wlid: "wlid://cluster-minikube/namespace-default/deployment-nginx",
	}
	ctx, err = s.ValidateScanCP(ctx, workload)
	require.NoError(t, err)
	sbom := domain.SBOM{
		Annotations: map[string]string{
			helpersv1.ImageIDMetadataKey:      "docker.io/library/nginx@sha256:04ba374043ccd2fc5c593885c0eacddebabd5ca375f9323666f28dfd5a9710e3",
			helpersv1.ImageTagMetadataKey:     "nginx",
			helpersv1.ResourceSizeMetadataKey: "3896210",
			helpersv1.StatusMetadataKey:       helpersv1.Learning,
		},
		Labels: map[string]string{
			helpersv1.ImageIDMetadataKey:   "docker-io-library-nginx-sha256-04ba374043ccd2fc5c593885c0eacdde",
			helpersv1.ImageNameMetadataKey: "docker-io-library-nginx",
		},
		Name:               imageSlug,
		Content:            fileToSyftDocument("../../adapters/v1/testdata/nginx-sbom.json"),
		SBOMCreatorVersion: sbomAdapter.Version(),
	}
	err = storageSBOM.StoreSBOM(ctx, sbom, false)
	require.NoError(t, err)
	ap := fileToContainerProfile("../../adapters/v1/testdata/nginx-ap.json")
	err = storageCP.StoreContainerProfile(ctx, ap)
	require.NoError(t, err)
	err = s.ScanCP(ctx)
	require.NoError(t, err)
	cvep, err := storageCVE.GetCVE(ctx, slug, sbomAdapter.Version(), cveAdapter.Version(), cveAdapter.DBVersion(ctx))
	require.NoError(t, err)
	assert.NotNil(t, cvep.Content)
}
