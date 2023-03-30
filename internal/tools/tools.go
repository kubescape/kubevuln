package tools

import (
	"regexp"
	"runtime/debug"
	"testing"

	"github.com/aquilax/truncate"
	"github.com/distribution/distribution/reference"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"gotest.tools/v3/assert"
	"k8s.io/apimachinery/pkg/util/validation"
)

func EnsureSetup(t *testing.T, errored bool) {
	assert.Assert(t, errored, "Error during test setup")
}

func PackageVersion(name string) string {
	bi, ok := debug.ReadBuildInfo()
	if ok {
		for _, dep := range bi.Deps {
			if dep.Path == name {
				return dep.Version
			}
		}
	}
	return "unknown"
}

var offendingChars = regexp.MustCompile("[@:/ .]")

func sanitize(s string) string {
	return truncate.Truncate(offendingChars.ReplaceAllString(s, "-"), 63, "", truncate.PositionEnd)
}

// LabelsFromImageID returns a map of labels from an image ID.
// Each label is sanitized and verified to be a valid DNS1123 label.
func LabelsFromImageID(imageID string) map[string]string {
	labels := map[string]string{}
	match := reference.ReferenceRegexp.FindStringSubmatch(imageID)
	labels[instanceidhandler.ImageNameAnnotationKey] = sanitize(match[1])
	labels[instanceidhandler.ImageTagAnnotationKey] = sanitize(match[2])
	// prune invalid labels
	for key, value := range labels {
		if errs := validation.IsDNS1123Label(value); len(errs) != 0 {
			delete(labels, key)
		}
	}
	return labels
}
