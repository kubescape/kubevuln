package tools

import (
	"testing"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/stretchr/testify/assert"
)

func TestEnsureSetup(t *testing.T) {
	EnsureSetup(t, true)
}

func TestPackageVersion(t *testing.T) {
	assert.True(t, PackageVersion("github.com/anchore/syft") == "unknown") // only works on compiled binaries
}

func TestLabelsFromImageID(t *testing.T) {
	tests := []struct {
		imageID string
		want    map[string]string
	}{
		{
			imageID: "myapp",
			want:    map[string]string{instanceidhandler.ImageIDMetadataKey: "myapp", instanceidhandler.ImageNameMetadataKey: "myapp"},
		},
		{
			imageID: "registry.com:8080/myapp",
			want:    map[string]string{instanceidhandler.ImageIDMetadataKey: "registry-com-8080-myapp", instanceidhandler.ImageNameMetadataKey: "registry-com-8080-myapp"},
		},
		{
			imageID: "registry.com:8080/myapp:tag",
			want:    map[string]string{instanceidhandler.ImageIDMetadataKey: "registry-com-8080-myapp-tag", instanceidhandler.ImageNameMetadataKey: "registry-com-8080-myapp", instanceidhandler.ImageTagMetadataKey: "tag"},
		},
		{
			imageID: "registry.com:8080/myapp@sha256:be178c0543eb17f5f3043021c9e5fcf30285e557a4fc309cce97ff9ca6182912",
			want:    map[string]string{instanceidhandler.ImageIDMetadataKey: "registry-com-8080-myapp-sha256-be178c0543eb17f5f3043021c9e5fcf3", instanceidhandler.ImageNameMetadataKey: "registry-com-8080-myapp"},
		},
		{
			imageID: "registry.com:8080/myapp:tag2@sha256:be178c0543eb17f5f3043021c9e5fcf30285e557a4fc309cce97ff9ca6182912",
			want:    map[string]string{instanceidhandler.ImageIDMetadataKey: "registry-com-8080-myapp-tag2-sha256-be178c0543eb17f5f3043021c9e", instanceidhandler.ImageNameMetadataKey: "registry-com-8080-myapp", instanceidhandler.ImageTagMetadataKey: "tag2"},
		},
		{
			imageID: "quay.io/matthiasb_1/storage@sha256:af6566ed56cbda1e3c2aed9f23da636d41302cccb7de78392c0a6769fb7ba593",
			want:    map[string]string{instanceidhandler.ImageIDMetadataKey: "quay-io-matthiasb-1-storage-sha256-af6566ed56cbda1e3c2aed9f23da", instanceidhandler.ImageNameMetadataKey: "quay-io-matthiasb-1-storage"},
		},
		{
			imageID: "602401143452.dkr.ecr.eu-west-1.amazonaws.com/eks/livenessprobe@sha256:f1129c3ed112e3882ee1ac17a40e5e2f4a1c332053c87f84f427b38552f58faa",
			want:    map[string]string{instanceidhandler.ImageIDMetadataKey: "602401143452-dkr-ecr-eu-west-1-amazonaws-com-eks-livenessprobe", instanceidhandler.ImageNameMetadataKey: "602401143452-dkr-ecr-eu-west-1-amazonaws-com-eks-livenessprobe"},
		},
		{
			imageID: "quay.io/prometheus/node-exporter@sha256:f2269e73124dd0f60a7d19a2ce1264d33d08a985aed0ee6b0b89d0be470592cd",
			want:    map[string]string{instanceidhandler.ImageIDMetadataKey: "quay-io-prometheus-node-exporter-sha256-f2269e73124dd0f60a7d19a", instanceidhandler.ImageNameMetadataKey: "quay-io-prometheus-node-exporter"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.imageID, func(t *testing.T) {
			got := LabelsFromImageID(tt.imageID)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeReference(t *testing.T) {
	type args struct {
		ref string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "image tag",
			args: args{
				ref: "nginx:latest",
			},
			want: "docker.io/library/nginx:latest",
		},
		{
			name: "image sha",
			args: args{
				ref: "nginx@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
			},
			want: "docker.io/library/nginx@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
		},
		{
			name: "image tag sha",
			args: args{
				ref: "nginx:latest@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
			},
			want: "docker.io/library/nginx:latest@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
		},
		{
			name: "repo image tag",
			args: args{
				ref: "docker.io/library/nginx:latest",
			},
			want: "docker.io/library/nginx:latest",
		},
		{
			name: "repo image sha",
			args: args{
				ref: "docker.io/library/nginx@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
			},
			want: "docker.io/library/nginx@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
		},
		{
			name: "repo image tag sha",
			args: args{
				ref: "docker.io/library/nginx:latest@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
			},
			want: "docker.io/library/nginx:latest@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
		},
		{
			name: "quay image tag",
			args: args{
				ref: "quay.io/kubescape/kubevuln:latest",
			},
			want: "quay.io/kubescape/kubevuln:latest",
		},
		{
			name: "quay image sha",
			args: args{
				ref: "quay.io/kubescape/kubevuln@sha256:616d1d4312551b94088deb6ddab232ecabbbff0c289949a0d5f12d4b527c3f8a",
			},
			want: "quay.io/kubescape/kubevuln@sha256:616d1d4312551b94088deb6ddab232ecabbbff0c289949a0d5f12d4b527c3f8a",
		},
		{
			name: "quay image tag sha",
			args: args{
				ref: "quay.io/kubescape/kubevuln:latest@sha256:616d1d4312551b94088deb6ddab232ecabbbff0c289949a0d5f12d4b527c3f8a",
			},
			want: "quay.io/kubescape/kubevuln:latest@sha256:616d1d4312551b94088deb6ddab232ecabbbff0c289949a0d5f12d4b527c3f8a",
		},
		{
			name: "some image other registry",
			args: args{
				ref: "public-registry.systest-ns-na6n:5000/nginx:test",
			},
			want: "public-registry.systest-ns-na6n:5000/nginx:test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NormalizeReference(tt.args.ref), "NormalizeReference(%v)", tt.args.ref)
		})
	}
}
