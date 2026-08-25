package tools

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"

	"github.com/aquilax/truncate"
	"github.com/distribution/reference"
	"github.com/gofrs/flock"
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
		err := os.RemoveAll(filepath.Join(dir, c.Name()))
		if err != nil {
			return err
		}
	}
	return nil
}

// activeTempDirUsers counts in-flight callers, within this process, that are actively reading
// from or writing to a stereoscope temp dir, so StartPeriodicTempDirSweep's periodic pass can
// tell a busy directory from an abandoned one. It is deliberately a single process-wide counter
// rather than something keyed per-directory: while any pull/catalog is in flight, none of the
// shared root's contents are safe to remove.
//
// cmd/http and cmd/sbom-scanner run as separate OS processes but mount the same /tmp volume in
// the kubevuln Pod (see the Helm chart's "tmp-dir" volume on both containers), sharing the same
// stereoscope temp-dir root on disk. activeTempDirUsers alone is invisible across that process
// boundary, so without the cross-process lease below, cmd/http's sweep could delete a directory
// an in-flight cmd/sbom-scanner cataloguing job is still reading from, or vice versa.
var activeTempDirUsers atomic.Int64

// activeScanLockFileName is the cross-process lease file BeginActiveTempDirUse and
// StartPeriodicTempDirSweep use, under the same dir they're both called with, to coordinate
// around the shared stereoscope temp-dir root across process boundaries (see activeTempDirUsers'
// doc comment). A flock-based lease is used instead of a marker file so a crashed process's hold
// is released automatically by the kernel/OS, with no orphaned-lock cleanup required.
const activeScanLockFileName = ".kubevuln-active-scan.lock"

func activeScanLockPath(dir string) string {
	return filepath.Join(dir, activeScanLockFileName)
}

// BeginActiveTempDirUse records that the caller is about to read from or write to a stereoscope
// temp dir under dir. Call the returned func exactly once when finished, however that happens:
// normal completion, error, or an abandoned goroutine that outlives its own caller's deadline
// (e.g. Syft cataloguing after a scan timeout — see adapters/v1/syft.go and
// pkg/sbomscanner/v1/server.go). While any caller is registered - in this process via
// activeTempDirUsers, or in another process sharing dir via the shared lock acquired here -
// StartPeriodicTempDirSweep skips its sweep entirely rather than risk deleting a directory still
// in use.
func BeginActiveTempDirUse(dir string) (end func()) {
	activeTempDirUsers.Add(1)
	var once sync.Once
	endFn := func() { once.Do(func() { activeTempDirUsers.Add(-1) }) }

	fl := flock.New(activeScanLockPath(dir))
	locked, err := fl.TryRLock()
	if err != nil || !locked {
		// Best-effort: cross-process coordination degrades to in-process-only tracking here,
		// which is exactly the pre-existing behavior rather than a regression.
		return endFn
	}
	return func() {
		endFn()
		_ = fl.Unlock()
	}
}

// acquireSweepLease takes the exclusive side of dir's active-scan lease and returns a release
// func. It reports false when another process holds the shared lease acquired by
// BeginActiveTempDirUse, i.e. is mid-use there. The lease is held for the whole sweep pass, so a
// concurrent BeginActiveTempDirUse cannot start between the check and the removal. A failure to
// determine this (e.g. dir does not exist yet) is treated as "no cross-process information," not
// as "busy" - activeTempDirUsers already covers this process's own in-flight uses regardless.
func acquireSweepLease(dir string) (release func(), ok bool) {
	fl := flock.New(activeScanLockPath(dir))
	locked, err := fl.TryLock()
	if err != nil {
		return func() {}, true
	}
	if !locked {
		return func() {}, false
	}
	return func() { _ = fl.Unlock() }, true
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
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			allErrs = errors.Join(allErrs, err)
			continue
		}
		removed++
	}
	return removed, allErrs
}

// StartPeriodicTempDirSweep runs CleanupStaleTempDirs immediately and then again on every
// tick of interval, until stop is closed (or the process's shutdown signal fires, for a
// context.Context's Done() channel). A single sweep at process startup only reclaims dirs
// orphaned by a *previous* process invocation (e.g. one killed by SIGKILL before its
// defer-based cleanup could run); it does nothing for dirs leaked by the *current*, still-running
// process, e.g. a registry pull that fails after stereoscope creates its image temp dir but
// before an image.Image exists to Cleanup() it (auth failures, transient registry errors,
// platform mismatches - none of which are crashes). Since kubevuln processes stay up for the
// life of a long-running pod rather than restarting per scan, those leaks would otherwise
// accumulate for the pod's entire uptime. onSweep, if non-nil, is invoked after every sweep
// (including the immediate one) with its outcome, so callers can log/record metrics without
// this function taking a dependency on either.
//
// Because activeTempDirUsers is a single process-wide counter (see its doc comment), a sweep is
// skipped in full whenever any pull or catalog is in flight anywhere in the process. On
// cmd/sbom-scanner, which intentionally allows concurrent CreateSBOM RPCs, sustained concurrent
// traffic can keep the counter above zero indefinitely, deferring sweeps beyond one interval.
// This only widens the reclaim window under continuous load; it never leaves a leaked dir
// unreclaimed forever, since the sweep still runs as soon as the process has an idle gap. The
// same applies across processes sharing dir, via acquireSweepLease.
func StartPeriodicTempDirSweep(stop <-chan struct{}, dir, prefix string, olderThan, interval time.Duration, onSweep func(removed int, err error)) {
	sweep := func() {
		if activeTempDirUsers.Load() > 0 {
			// A pull or a cataloguing pass that outlived its own timeout is still using the
			// shared temp dir root; removing anything now could delete files out from under it.
			// Skip this pass entirely and let the next tick re-check.
			return
		}
		release, ok := acquireSweepLease(dir)
		if !ok {
			// Another process sharing dir (see activeTempDirUsers' doc comment) is mid-use, per
			// the lease acquired in its own BeginActiveTempDirUse call. Same reasoning as above,
			// just visible across the process boundary rather than within this one.
			return
		}
		defer release()
		removed, err := CleanupStaleTempDirs(dir, prefix, olderThan)
		if onSweep != nil {
			onSweep(removed, err)
		}
	}
	sweep()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				sweep()
			}
		}
	}()
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
