package services

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/docker/docker/api/types/registry"
	"github.com/kubescape/kubevuln/adapters"
	v1 "github.com/kubescape/kubevuln/adapters/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanService_GenerateSBOM(t *testing.T) {
	tests := []struct {
		createSBOMError bool
		name            string
		sbom            domain.SBOM
		storage         bool
		getError        bool
		storeError      bool
		timeout         bool
		toomanyrequests bool
		workload        bool
		wantErr         bool
	}{
		{
			name:     "phase 1, no workload",
			workload: false,
			wantErr:  true,
		},
		{
			name:     "phase 1",
			workload: true,
			wantErr:  false,
		},
		{
			name:            "phase 1, createSBOM error",
			createSBOMError: true,
			workload:        true,
			wantErr:         true,
		},
		{
			name:     "phase 1, timeout",
			timeout:  true,
			workload: true,
			wantErr:  false, // we no longer check for timeout
		},
		{
			name:            "phase 1, too many requests",
			toomanyrequests: true,
			workload:        true,
			wantErr:         true,
		},
		{
			name:     "phase 2, get SBOM failed",
			storage:  true,
			getError: true,
			workload: true,
			wantErr:  false,
		},
		{
			name:       "phase 2, store SBOM failed",
			storage:    true,
			storeError: true,
			workload:   true,
			wantErr:    true,
		},
		{
			name:     "phase 2, create and store SBOM",
			storage:  true,
			workload: true,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbomAdapter := adapters.NewMockSBOMAdapter(tt.createSBOMError, tt.timeout, tt.toomanyrequests)
			storage := repositories.NewMemoryStorage(tt.getError, tt.storeError)
			s := NewScanService(sbomAdapter,
				storage,
				adapters.NewMockCVEAdapter(),
				storage,
				adapters.NewMockPlatform(false),
				tt.storage,
				false, true)
			ctx := context.TODO()

			workload := domain.ScanCommand{
				ImageSlug: "imageSlug",
				ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
			}
			workload.CredentialsList = []registry.AuthConfig{
				{
					Username: "test",
					Password: "test",
				},
				{
					RegistryToken: "test",
				},
				{
					Auth: "test",
				},
			}
			workload.Args = map[string]interface{}{
				domain.AttributeUseHTTP:       false,
				domain.AttributeSkipTLSVerify: false,
			}
			if tt.workload {
				ctx, _ = s.ValidateGenerateSBOM(ctx, workload)
			}
			if err := s.GenerateSBOM(ctx); (err != nil) != tt.wantErr {
				t.Errorf("GenerateSBOM() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.toomanyrequests {
				_, err := s.ValidateGenerateSBOM(ctx, workload)
				assert.Equal(t, domain.ErrTooManyRequests, err)
			}
		})
	}
}

func TestScanService_ScanCVE(t *testing.T) {
	tests := []struct {
		createSBOMError bool
		name            string
		instanceID      string
		emptyWlid       bool
		cveManifest     bool
		sbom            bool
		storage         bool
		getErrorCVE     bool
		getErrorSBOM    bool
		storeErrorCVE   bool
		storeErrorSBOM  bool
		timeout         bool
		toomanyrequests bool
		workload        bool
		wantCvep        bool
		wantEmptyReport bool
		wantErr         bool
	}{
		{
			name:     "no workload",
			workload: false,
			wantErr:  true,
		},
		{
			name:     "no storage",
			workload: true,
			wantErr:  false,
		},
		{
			name:            "create SBOM error",
			createSBOMError: true,
			workload:        true,
			wantErr:         true,
		},
		{
			name:            "create SBOM too many requests",
			toomanyrequests: true,
			workload:        true,
			wantErr:         true,
		},
		{
			name:      "empty wlid",
			emptyWlid: true,
			storage:   true,
			workload:  true,
			wantErr:   false,
		},
		{
			name:     "first scan",
			storage:  true,
			workload: true,
			wantErr:  false,
		},
		{
			name:            "second scan",
			storage:         true,
			cveManifest:     true,
			sbom:            true,
			workload:        true,
			wantEmptyReport: false,
			wantErr:         false,
		},
		{
			name:         "get SBOM failed",
			getErrorSBOM: true,
			storage:      true,
			workload:     true,
			wantErr:      false,
		},
		{
			name:           "store SBOM failed",
			storeErrorSBOM: true,
			storage:        true,
			workload:       true,
			wantErr:        false,
		},
		{
			name:        "get CVE failed",
			getErrorCVE: true,
			storage:     true,
			workload:    true,
			wantErr:     false,
		},
		{
			name:          "store CVE failed",
			storeErrorCVE: true,
			storage:       true,
			workload:      true,
			wantErr:       false,
		},
		{
			name:     "timeout SBOM",
			sbom:     true,
			storage:  true,
			timeout:  true,
			workload: true,
			wantErr:  true,
		},
		{
			name:       "with SBOMp",
			sbom:       true,
			instanceID: "ee9bdd0adec9ce004572faf3492f583aa82042a8b3a9d5c7d9179dc03c531eef",
			storage:    true,
			workload:   true,
			wantCvep:   true,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageHash := "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137"
			wlid := "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy"
			if tt.emptyWlid {
				wlid = ""
			}
			sbomAdapter := adapters.NewMockSBOMAdapter(tt.createSBOMError, tt.timeout, tt.toomanyrequests)
			cveAdapter := adapters.NewMockCVEAdapter()
			storageSBOM := repositories.NewMemoryStorage(tt.getErrorSBOM, tt.storeErrorSBOM)
			storageCVE := repositories.NewMemoryStorage(tt.getErrorCVE, tt.storeErrorCVE)
			s := NewScanService(sbomAdapter,
				storageSBOM,
				cveAdapter,
				storageCVE,
				adapters.NewMockPlatform(tt.wantEmptyReport),
				tt.storage,
				false, true)
			ctx := context.TODO()
			s.Ready(ctx)

			workload := domain.ScanCommand{
				ImageSlug: "imageSlug",
				ImageHash: imageHash,
				Wlid:      wlid,
			}
			if tt.instanceID != "" {
				workload.InstanceID = tt.instanceID
			}
			if tt.workload {
				var err error
				ctx, err = s.ValidateScanCVE(ctx, workload)
				require.NoError(t, err)
			}
			if tt.sbom {
				sbom, err := sbomAdapter.CreateSBOM(ctx, "imageSlug", imageHash, "", domain.RegistryOptions{})
				require.NoError(t, err)
				_ = storageSBOM.StoreSBOM(ctx, sbom)
				if tt.cveManifest {
					cve, err := cveAdapter.ScanSBOM(ctx, sbom)
					require.NoError(t, err)
					_ = storageCVE.StoreCVE(ctx, cve, false)
				}
			}
			var sbomp domain.SBOM
			if tt.instanceID != "" {
				var err error
				sbomp, err = sbomAdapter.CreateSBOM(ctx, tt.instanceID, tt.instanceID, "", domain.RegistryOptions{})
				require.NoError(t, err)
				sbomp.Labels = map[string]string{"foo": "bar"}
				_ = storageSBOM.StoreSBOM(ctx, sbomp)
			}
			if err := s.ScanCVE(ctx); (err != nil) != tt.wantErr {
				t.Errorf("ScanCVE() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.toomanyrequests {
				_, err := s.ValidateScanCVE(ctx, workload)
				assert.Equal(t, domain.ErrTooManyRequests, err)
			}
			if tt.wantCvep {
				cvep, err := storageCVE.GetCVE(ctx, sbomp.Name, sbomAdapter.Version(), cveAdapter.Version(ctx), cveAdapter.DBVersion(ctx))
				require.NoError(t, err)
				assert.NotNil(t, cvep.Labels)
			}
		})
	}
}

func fileContent(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func fileToSyftDocument(path string) *v1beta1.SyftDocument {
	sbom := v1beta1.SyftDocument{}
	_ = json.Unmarshal(fileContent(path), &sbom)
	return &sbom
}

func TestScanService_NginxTest(t *testing.T) {
	imageHash := "docker.io/library/nginx@sha256:32fdf92b4e986e109e4db0865758020cb0c3b70d6ba80d02fe87bad5cc3dc228"
	imageSlug := "name"
	instanceID := "1c83b589d90ba26957627525e08124b1a24732755a330924f7987e9d9e3952c1"
	ctx := context.TODO()
	sbomAdapter := adapters.NewMockSBOMAdapter(false, false, false)
	go func() {
		_ = http.ListenAndServe(":8000", http.FileServer(http.Dir("../../adapters/v1/testdata")))
	}()
	cveAdapter := v1.NewGrypeAdapterFixedDB()
	storageSBOM := repositories.NewMemoryStorage(false, false)
	storageCVE := repositories.NewMemoryStorage(false, false)
	platform := adapters.NewMockPlatform(false)
	s := NewScanService(sbomAdapter, storageSBOM, cveAdapter, storageCVE, platform, true, false, true)
	s.Ready(ctx)
	workload := domain.ScanCommand{
		ContainerName: "nginx",
		ImageHash:     imageHash,
		ImageSlug:     imageSlug,
		ImageTag:      "docker.io/library/nginx:1.14.1",
		InstanceID:    instanceID,
		Wlid:          "wlid://cluster-minikube/namespace-default/deployment-nginx",
	}
	ctx, _ = s.ValidateScanCVE(ctx, workload)
	sbom := domain.SBOM{
		Name:               imageSlug,
		Content:            fileToSyftDocument("../../adapters/v1/testdata/nginx-sbom.json"),
		SBOMCreatorVersion: sbomAdapter.Version(),
	}
	err := storageSBOM.StoreSBOM(ctx, sbom)
	require.NoError(t, err)
	sbomp := domain.SBOM{
		Name:               instanceID,
		Content:            fileToSyftDocument("../../adapters/v1/testdata/nginx-filtered-sbom.json"),
		SBOMCreatorVersion: sbomAdapter.Version(),
	}
	err = storageSBOM.StoreSBOM(ctx, sbomp)
	require.NoError(t, err)
	err = s.ScanCVE(ctx)
	require.NoError(t, err)
	cvep, err := storageCVE.GetCVE(ctx, sbomp.Name, sbomAdapter.Version(), cveAdapter.Version(ctx), cveAdapter.DBVersion(ctx))
	require.NoError(t, err)
	assert.NotNil(t, cvep.Content)
}

func TestScanService_ValidateGenerateSBOM(t *testing.T) {
	tests := []struct {
		name     string
		workload domain.ScanCommand
		wantErr  bool
	}{
		{
			name:     "missing imageSlug",
			workload: domain.ScanCommand{},
			wantErr:  true,
		},
		{
			name: "with imageSlug",
			workload: domain.ScanCommand{
				ImageSlug: "imageSlug",
				ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanService(adapters.NewMockSBOMAdapter(false, false, false),
				repositories.NewMemoryStorage(false, false),
				adapters.NewMockCVEAdapter(),
				repositories.NewMemoryStorage(false, false),
				adapters.NewMockPlatform(false),
				false, false, true)
			_, err := s.ValidateGenerateSBOM(context.TODO(), tt.workload)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGenerateSBOM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestScanService_ValidateScanCVE(t *testing.T) {
	tests := []struct {
		name     string
		workload domain.ScanCommand
		wantErr  bool
	}{
		{
			name:     "missing Wlid",
			workload: domain.ScanCommand{},
			wantErr:  true,
		},
		{
			name: "missing ImageHash",
			workload: domain.ScanCommand{
				Wlid: "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy",
			},
			wantErr: true,
		},
		{
			name: "with Wlid and ImageHash",
			workload: domain.ScanCommand{
				ImageSlug: "imageSlug",
				ImageHash: "k8s.gcr.io/kube-proxy@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137",
				Wlid:      "wlid://cluster-minikube/namespace-kube-system/daemonset-kube-proxy",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanService(adapters.NewMockSBOMAdapter(false, false, false),
				repositories.NewMemoryStorage(false, false),
				adapters.NewMockCVEAdapter(),
				repositories.NewMemoryStorage(false, false),
				adapters.NewMockPlatform(false),
				false, false, true)
			_, err := s.ValidateScanCVE(context.TODO(), tt.workload)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScanCVE() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestScanService_ScanRegistry(t *testing.T) {
	tests := []struct {
		createSBOMError bool
		name            string
		timeout         bool
		toomanyrequests bool
		workload        bool
		wantErr         bool
	}{
		{
			name:     "no workload",
			workload: false,
			wantErr:  true,
		},
		{
			name:            "create SBOM error",
			createSBOMError: true,
			workload:        true,
			wantErr:         true,
		},
		{
			name:     "timeout SBOM",
			timeout:  true,
			workload: true,
			wantErr:  true,
		},
		{
			name:            "toomanyrequests SBOM",
			toomanyrequests: true,
			workload:        true,
			wantErr:         true,
		},
		{
			name:     "scan",
			workload: true,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbomAdapter := adapters.NewMockSBOMAdapter(tt.createSBOMError, tt.timeout, tt.toomanyrequests)
			storage := repositories.NewMemoryStorage(false, false)
			s := NewScanService(sbomAdapter,
				storage,
				adapters.NewMockCVEAdapter(),
				storage,
				adapters.NewMockPlatform(false),
				false, false, true)
			ctx := context.TODO()
			workload := domain.ScanCommand{
				ImageSlug:          "imageSlug",
				ImageTagNormalized: "k8s.gcr.io/kube-proxy:v1.24.3",
			}
			workload.CredentialsList = []registry.AuthConfig{
				{
					Username: "test",
					Password: "test",
				},
				{
					RegistryToken: "test",
				},
				{
					Auth: "test",
				},
			}
			if tt.workload {
				var err error
				ctx, _ = s.ValidateScanRegistry(ctx, workload)
				require.NoError(t, err)
			}
			if err := s.ScanRegistry(ctx); (err != nil) != tt.wantErr {
				t.Errorf("ScanRegistry() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.toomanyrequests {
				_, err := s.ValidateScanRegistry(ctx, workload)
				assert.Equal(t, domain.ErrTooManyRequests, err)
			}
		})
	}
}

func TestScanService_ValidateScanRegistry(t *testing.T) {
	tests := []struct {
		name     string
		workload domain.ScanCommand
		wantErr  bool
	}{
		{
			name:     "missing imageID",
			workload: domain.ScanCommand{},
			wantErr:  true,
		},
		{
			name: "with imageID",
			workload: domain.ScanCommand{
				ImageSlug:          "imageSlug",
				ImageTagNormalized: "k8s.gcr.io/kube-proxy:v1.24.3",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanService(adapters.NewMockSBOMAdapter(false, false, false),
				repositories.NewMemoryStorage(false, false),
				adapters.NewMockCVEAdapter(),
				repositories.NewMemoryStorage(false, false),
				adapters.NewMockPlatform(false),
				false, false, true)
			_, err := s.ValidateScanRegistry(context.TODO(), tt.workload)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScanRegistry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_generateScanID(t *testing.T) {
	type args struct {
		workload domain.ScanCommand
		version  string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "generate scanID with imageHash",
			args: args{
				workload: domain.ScanCommand{
					ImageTagNormalized: "k8s.gcr.io/kube-proxy:v1.24.3",
					ImageHash:          "sha256:6f9c1c5b5b1b2b3b4b5b6b7b8b9b0b1b2b3b4b5b6b7b8b9b0b1b2b3b4b5b6b7b",
				},
			},
			want: "2d0ee020566e8ff66542c5cd9e324111731c6a49d237fea3bd880448dac1a37f",
		},
		{
			name: "generate scanID with instanceID",
			args: args{
				workload: domain.ScanCommand{
					InstanceID: "InstanceID",
				},
				version: "1.0.0",
			},
			want: "InstanceID-1-0-0",
		},
		{
			name: "generate scanID with instanceID without version",
			args: args{
				workload: domain.ScanCommand{
					InstanceID: "InstanceID",
				},
				version: "",
			},
			want: "InstanceID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := generateScanID(tt.args.workload, tt.args.version); got != tt.want {
				t.Errorf("generateScanID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_registryCredentialsFromCredentialsList(t *testing.T) {
	creds := []registry.AuthConfig{
		{
			ServerAddress: "quay.io",
			Auth:          "YXJtb3NlYyt0ZXN0cm9ib3QxOmR1bW15UGFzc3dvcmQ=",
			Username:      "armosec+testrobot1",
			Password:      "dummyPassword",
		},
		{
			ServerAddress: "https://index.docker.io/v1/",
			Username:      "test_user",
			Password:      "dummyPassword",
			Email:         "test_user@gmail.com",
			Auth:          "dGVzdF91c2VyOmR1bW15UGFzc3dvcmQ=",
		},
		{
			ServerAddress: "quay.io",
			Auth:          "YXJtb3NlYyt0ZXN0cm9ib3QyOmR1bW15UGFzc3dvcmQxMTE=",
			Username:      "armosec+testrobot2",
			Password:      "dummyPassword111",
		},
	}
	registryCredentials := registryCredentialsFromCredentialsList(creds)
	assert.Equal(t, 3, len(registryCredentials))
	assert.Equal(t, "quay.io", registryCredentials[0].Authority)
	assert.Equal(t, "armosec+testrobot1", registryCredentials[0].Username)
	assert.Equal(t, "dummyPassword", registryCredentials[0].Password)
	assert.Equal(t, "index.docker.io", registryCredentials[1].Authority)
	assert.Equal(t, "test_user", registryCredentials[1].Username)
	assert.Equal(t, "dummyPassword", registryCredentials[1].Password)
	assert.Equal(t, "quay.io", registryCredentials[2].Authority)
	assert.Equal(t, "armosec+testrobot2", registryCredentials[2].Username)
	assert.Equal(t, "dummyPassword111", registryCredentials[2].Password)
}

func Test_parseAuthorityFromServerAddress(t *testing.T) {
	assert.Equal(t, "", parseAuthorityFromServerAddress(""))
	assert.Equal(t, "index.docker.io", parseAuthorityFromServerAddress("https://index.docker.io/v1/"))
	assert.Equal(t, "quay.io", parseAuthorityFromServerAddress("quay.io"))
	assert.Equal(t, "x.quay.io", parseAuthorityFromServerAddress("https://x.quay.io"))
	assert.Equal(t, "europe-docker.pkg.dev", parseAuthorityFromServerAddress("europe-docker.pkg.dev/xxx/xxx"))
}
