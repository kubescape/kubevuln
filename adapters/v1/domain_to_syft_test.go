package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_domainJSONToSyft(t *testing.T) {
	type args struct {
		data []byte
	}
	type source struct {
		id   string
		name string
	}

	type want struct {
		source                source
		artifacts             int // number of artifacts
		artifactRelationships int // number of artifact relationships
		files                 int // number of files
	}
	tests := []struct {
		name    string
		args    args
		want    want
		wantErr bool
	}{
		{
			name: "valid alpine SBOM",
			args: args{
				data: fileContent("testdata/alpine-sbom.json"),
			},
			want: want{
				artifacts:             15,
				artifactRelationships: 129,
				files:                 78,
				source: source{
					id:   "fd6275a37d2472b9d3be70c3261087b8d65e441c21342ae7313096312bcda2b3",
					name: "library/alpine",
				},
			},
		}, {
			name: "valid nginx SBOM",
			args: args{
				data: fileContent("testdata/nginx-sbom.json"),
			},
			want: want{
				artifacts:             109,
				artifactRelationships: 3361,
				files:                 2859,
				source: source{
					id:   "de6550380fa1f872aa5f4174fa66d0e364becb92958afba192ea9437a53ade89",
					name: "nginx",
				},
			},
		}, {
			name: "valid hello-world SBOM",
			args: args{
				data: fileContent("testdata/hello-world-sbom.json"),
			},
			want: want{
				artifacts:             0,
				artifactRelationships: 0,
				files:                 0,
				source: source{
					id:   "03a75d703fcd471cc09ed0dfffde55b74d95598343411e7fa3bcebc18d91bb8b",
					name: "library/hello-world",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := domainJSONToSyft(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("syftJSONToDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.want.artifacts, got.Artifacts.Packages.PackageCount())
			assert.Equal(t, tt.want.artifactRelationships, len(got.Relationships))
			assert.Equal(t, tt.want.files, len(got.AllCoordinates()))
			assert.Equal(t, tt.want.source.id, got.Source.ID)
			assert.Equal(t, tt.want.source.name, got.Source.Name)
		})
	}
}
