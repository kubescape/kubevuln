package v1

import (
	"errors"
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
				artifactRelationships: 128,
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

func Test_domainJSONToSyft_DropsErrors(t *testing.T) {
	// A simple SBOM with an unknown relationship type and a bad CPE.
	// We just want to ensure it parses without panic, and show that errors are swallowed.
	sbomData := []byte(`{
  "artifacts": [
    {
      "id": "pkg1",
      "name": "bad-cpe-pkg",
      "cpes": [
        {
          "value": "invalid-cpe-format",
          "source": "test"
        }
      ]
    },
    {
      "id": "pkg2",
      "name": "child-pkg"
    }
  ],
  "artifactRelationships": [
    {
      "parent": "pkg1",
      "child": "pkg2",
      "type": "unknown-completely-invalid-relationship"
    }
  ],
  "source": {
    "id": "source1",
    "name": "test-source"
  }
}`)

	got, err := domainJSONToSyft(sbomData)
	assert.NoError(t, err)
	
	// The bad package is kept but its invalid CPE is silently dropped
	assert.Equal(t, 2, got.Artifacts.Packages.PackageCount())
	pkgCountWithCPEs := 0
	for _, p := range got.Artifacts.Packages.Sorted() {
		if len(p.CPEs) > 0 {
			pkgCountWithCPEs++
		}
	}
	assert.Equal(t, 0, pkgCountWithCPEs, "expected CPEs to be dropped silently")

	// The unknown relationship is silently dropped
	assert.Equal(t, 0, len(got.Relationships), "expected relationship to be dropped silently")
}

func Test_deduplicateErrors(t *testing.T) {
	tests := []struct {
		name string
		errs []error
		want []string
	}{
		{
			name: "no errors",
			errs: nil,
			want: nil,
		},
		{
			name: "one error is reported once",
			errs: []error{errors.New("bad cpe")},
			want: []string{`"bad cpe" occurred 1 time(s)`},
		},
		{
			name: "repeats collapse into a count",
			errs: []error{errors.New("bad cpe"), errors.New("bad cpe"), errors.New("bad cpe")},
			want: []string{`"bad cpe" occurred 3 time(s)`},
		},
		{
			name: "distinct errors each keep their own count",
			errs: []error{
				errors.New("bad cpe"),
				errors.New("unknown relationship"),
				errors.New("bad cpe"),
			},
			want: []string{
				`"bad cpe" occurred 2 time(s)`,
				`"unknown relationship" occurred 1 time(s)`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// order comes from a map range, so compare as a set
			assert.ElementsMatch(t, tt.want, deduplicateErrors(tt.errs))
		})
	}
}

// warnConversionErrors returns its input untouched whatever the errors say, so
// the only thing that reaches deduplicateErrors on a real conversion is the log
// line. This keeps that call covered.
func Test_warnConversionErrors_PassesConvertedThrough(t *testing.T) {
	converted := []string{"a", "b"}
	got := warnConversionErrors(converted, []error{errors.New("x"), errors.New("x")})
	assert.Equal(t, converted, got)
}
