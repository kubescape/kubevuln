package tools

import (
	"encoding/json"
	"os"
	"path"
	"regexp"
	"runtime/debug"
	"strings"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"

	"github.com/aquilax/truncate"
	"github.com/distribution/distribution/reference"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/util/validation"
)

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

var offendingChars = regexp.MustCompile("[@:/ ._]")

// SanitizeLabel sanitizes a string to be a valid DNS1123 label.
func SanitizeLabel(s string) string {
	s2 := truncate.Truncate(offendingChars.ReplaceAllString(s, "-"), 63, "", truncate.PositionEnd)
	// remove trailing dash
	if len(s2) > 0 && s2[len(s2)-1] == '-' {
		return s2[:len(s2)-1]
	}
	return s2
}

// LabelsFromImageID returns a map of labels from an image ID.
// Each label is sanitized and verified to be a valid DNS1123 label.
func LabelsFromImageID(imageID string) map[string]string {
	labels := map[string]string{
		helpersv1.ArtifactTypeMetadataKey: helpersv1.ImageArtifactType,
	}
	ref, err := reference.Parse(imageID)
	if err != nil {
		return labels
	}
	if named, ok := ref.(reference.Named); ok {
		labels[helpersv1.ImageIDMetadataKey] = SanitizeLabel(named.String())
		labels[helpersv1.ImageNameMetadataKey] = SanitizeLabel(named.Name())
	}
	if tagged, ok := ref.(reference.Tagged); ok {
		labels[helpersv1.ImageTagMetadataKey] = SanitizeLabel(tagged.Tag())
	}
	// prune invalid labels
	for key, value := range labels {
		if errs := validation.IsDNS1123Label(value); len(errs) != 0 {
			delete(labels, key)
		}
	}
	return labels
}

func FileContent(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

func FileToSBOM(path string) *v1beta1.SyftDocument {
	sbom := v1beta1.SyftDocument{}
	_ = json.Unmarshal(FileContent(path), &sbom)
	return &sbom
}

func FileToCVEManifest(path string) domain.CVEManifest {
	var cve domain.CVEManifest
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(b, &cve)
	if err != nil {
		panic(err)
	}
	return cve
}

func DeleteContents(dir string) error {
	d, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, c := range d {
		err := os.RemoveAll(path.Join([]string{dir, c.Name()}...))
		if err != nil {
			return err
		}
	}
	return nil
}

func NormalizeReference(ref string) string {
	n, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return ref
	}
	return reference.TagNameOnly(n).String()
}

// ReferenceMatchForms returns the equivalent forms of an image reference that a
// user-written pattern may reasonably be matched against, most specific first:
// the reference itself, the same reference without its digest, and the bare
// repository name. Duplicates are omitted, so a plain "repo:tag" yields only
// two forms and an unparsable reference only itself.
//
// A normalized reference keeps any digest it was deployed with
// ("docker.io/library/nginx:1.25@sha256:..."), so matching against the
// reference alone would never match a pattern written against the tag.
func ReferenceMatchForms(ref string) []string {
	forms := []string{ref}
	n, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return forms
	}
	name := n.Name()
	if tagged, ok := n.(reference.NamedTagged); ok {
		forms = appendUnique(forms, name+":"+tagged.Tag())
	}
	return appendUnique(forms, name)
}

func appendUnique(forms []string, form string) []string {
	for _, f := range forms {
		if f == form {
			return forms
		}
	}
	return append(forms, form)
}

func RemoveContainerFromSlug(slug, container string) string {
	i := strings.LastIndex(slug, container)
	if i == -1 {
		return slug
	}
	return slug[:i-1]
}
