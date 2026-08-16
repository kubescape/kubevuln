package tools

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

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

// offendingChars matches everything a DNS1123 label may not contain, rather than an
// enumerated set. Listing the characters seen in image references ("[@:/ ._]") left anything
// unlisted to pass through unchanged and fail validation, so the label was dropped: "foo+bar"
// and non-ASCII input both survived substitution intact. Applied after lowercasing, so no
// uppercase reaches it.
var offendingChars = regexp.MustCompile("[^a-z0-9-]")

// SanitizeLabel sanitizes a string to be a valid DNS1123 label.
//
// Lowercasing and trimming both ends matter because LabelsFromImageID drops any label that
// fails validation, so anything this leaves invalid disappears silently rather than being
// stored in a degraded form:
//
//   - A DNS1123 label must be lowercase, while an image tag may legally contain uppercase
//     (the reference grammar allows [a-zA-Z0-9_][a-zA-Z0-9._-]*), so a tag such as v1.0-RC1
//     produced an invalid label.
//   - A DNS1123 label must start and end alphanumeric, and adjacent offending characters
//     collapse into several dashes (v1_. becomes v1--), so stripping a single trailing dash
//     was not enough. Truncation at 63 can also land on a dash, and a leading offending
//     character produces a leading one.
func SanitizeLabel(s string) string {
	s2 := truncate.Truncate(offendingChars.ReplaceAllString(strings.ToLower(s), "-"), 63, "", truncate.PositionEnd)
	return strings.Trim(s2, "-")
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
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil
	}
	return b
}

func FileToSBOM(path string) *v1beta1.SyftDocument {
	sbom := v1beta1.SyftDocument{}
	_ = json.Unmarshal(FileContent(path), &sbom)
	return &sbom
}

func FileToCVEManifest(path string) domain.CVEManifest {
	var cve domain.CVEManifest
	b, err := os.ReadFile(filepath.Clean(path))
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

// CleanupStaleTempDirs removes directories under dir whose names start with prefix and whose
// mtime is older than olderThan. It is a best-effort startup sweep to reclaim disk space left
// by processes killed before their defer-based cleanup could run (e.g. SIGKILL from OOM or
// Kubernetes terminationGracePeriodSeconds expiry).
//
// It returns the number of directories removed and a joined error of all failures encountered.
// A non-nil error never blocks startup — callers should log and continue.
func CleanupStaleTempDirs(dir, prefix string, olderThan time.Duration) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-olderThan)
	removed := 0
	var allErrs error
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			allErrs = errors.Join(allErrs, err)
			continue
		}
		if !info.ModTime().Before(cutoff) {
			continue // young enough — may belong to a live sidecar scan
		}
		if err := os.RemoveAll(path.Join(dir, e.Name())); err != nil {
			allErrs = errors.Join(allErrs, err)
			continue
		}
		removed++
	}
	return removed, allErrs
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
