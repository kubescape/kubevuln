package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
	grypeversion "github.com/anchore/grype/grype/version"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/containerscan"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type Target struct {
	directoryMetadata *source.DirectoryMetadata
	imageMetadata     *source.ImageMetadata
}

func NewTargetFromSource(src *v1beta1.Source) (Target, error) {
	var target Target
	if src == nil {
		return target, fmt.Errorf("grype document source is nil")
	}

	switch src.Type {
	case "directory":
		// Try unmarshaling into DirectoryMetadata first
		var directoryMetadata source.DirectoryMetadata
		if err := json.Unmarshal(src.Target, &directoryMetadata); err == nil {
			target.directoryMetadata = &directoryMetadata
		} else {
			// Fallback: try unmarshaling as a raw string path
			var path string
			if err := json.Unmarshal(src.Target, &path); err != nil {
				return target, fmt.Errorf("failed to unmarshal directory target as either DirectoryMetadata or string: %w", err)
			}
			if filepath.IsAbs(path) {
				target.directoryMetadata = &source.DirectoryMetadata{Path: path}
			} else {
				return target, fmt.Errorf("expected a 'directory' to represent a valid path but got: %s", path)
			}
		}
	// defaults to image
	default:
		var imageMetadata source.ImageMetadata
		err := json.Unmarshal(src.Target, &imageMetadata)
		if err != nil {
			return target, err
		}
		target.imageMetadata = &imageMetadata
	}

	return target, nil
}

func (s *Target) IsImageTarget() bool {
	return s.imageMetadata != nil
}
func (s *Target) IsDirectoryTarget() bool {
	return s.directoryMetadata != nil
}

func (s *Target) GetImageMetadata() *source.ImageMetadata {
	return s.imageMetadata
}

func (s *Target) GetDirectoryMetadata() *source.DirectoryMetadata {
	return s.directoryMetadata
}

func DomainToArmo(ctx context.Context, grypeDocument v1beta1.GrypeDocument, vulnerabilityExceptionPolicyList []armotypes.VulnerabilityExceptionPolicy) ([]containerscan.CommonContainerVulnerabilityResult, error) {
	var vulnerabilityResults []containerscan.CommonContainerVulnerabilityResult

	// retrieve timestamp from context
	timestamp, ok := ctx.Value(domain.TimestampKey{}).(int64)
	if !ok {
		return vulnerabilityResults, domain.ErrMissingTimestamp
	}
	// retrieve scanID from context
	scanID, ok := ctx.Value(domain.ScanIDKey{}).(string)
	if !ok {
		return vulnerabilityResults, domain.ErrMissingScanID
	}
	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return vulnerabilityResults, domain.ErrCastingWorkload
	}

	// Built once per scan and reused for every match below, instead of re-walking the full
	// exception list per match.
	exceptionIndex := buildCVEExceptionIndex(vulnerabilityExceptionPolicyList)

	if grypeDocument.Source != nil {
		// generate a map of child to parent
		parentLayerHash := ""
		parentLayer := map[string]string{
			dummyLayer: parentLayerHash,
		}
		// ...and one of layer to its position in the image, so the earliest layer a package
		// appears in can be picked directly rather than by walking the chain from the root.
		layerPosition := map[string]int{}

		target, err := NewTargetFromSource(grypeDocument.Source)
		if err != nil {
			return vulnerabilityResults, err
		}

		if target.IsImageTarget() {
			imageMetadata := target.GetImageMetadata()
			for i, layer := range imageMetadata.Layers {
				parentLayer[layer.Digest] = parentLayerHash
				parentLayerHash = layer.Digest
				layerPosition[layer.Digest] = i
			}
		}

		// iterate over all vulnerabilities
		for _, m := range grypeDocument.Matches {
			var isFixed int
			description := m.Vulnerability.Description
			link := linkToVuln(m.Vulnerability.ID)
			fixed, version := hasKnownFix(m)
			if fixed {
				isFixed = 1
			}
			if description == "" && len(m.RelatedVulnerabilities) > 0 {
				description = m.RelatedVulnerabilities[0].Description
			}
			// create a vulnerability result for this vulnerability
			vulnerabilityResult := containerscan.CommonContainerVulnerabilityResult{
				IsLastScan:      1,
				WLID:            workload.Wlid,
				ContainerScanID: scanID,
				Layers:          []containerscan.ESLayer{},
				Timestamp:       timestamp,
				IsFixed:         isFixed,
				RelevantLinks: []string{
					link,
					m.Vulnerability.DataSource,
				},
				Vulnerability: containerscan.Vulnerability{
					Name:               m.Vulnerability.ID,
					ImageID:            workload.ImageHash,
					ImageTag:           workload.ImageTagNormalized,
					RelatedPackageName: m.Artifact.Name,
					PackageVersion:     m.Artifact.Version,
					Link:               link,
					Description:        description,
					Severity:           m.Vulnerability.Severity,
					SeverityScore:      containerscan.SeverityStr2Score[m.Vulnerability.Severity],
					Fixes: []containerscan.FixedIn{
						{
							Name:    m.Vulnerability.Fix.State,
							ImgTag:  workload.ImageTagNormalized,
							Version: version,
						},
					},
					PackageType:      string(m.Artifact.Type),
					ExceptionApplied: scopedToSubcomponent(exceptionIndex.lookup(m.Vulnerability.ID, isFixed == 1), m.Artifact.PURL),
					IsRelevant:       nil, // TODO add relevancy here?
					Coordinates:      syftCoordinatesToCoordinates(m.Artifact.Locations),
				},
			}
			// add RCE information
			vulnerabilityResult.Categories.IsRCE = vulnerabilityResult.IsRCE()
			// add layer information
			// make sure we have at least one location
			if len(m.Artifact.Locations) == 0 {
				m.Artifact.Locations = []v1beta1.SyftCoordinates{
					{
						FileSystemID: dummyLayer,
					},
				}
			}
			// iterate over locations
			for _, location := range m.Artifact.Locations {
				// create a layer
				layer := containerscan.ESLayer{
					LayerHash:       location.FileSystemID,
					ParentLayerHash: parentLayer[location.FileSystemID],
				}
				// add layer to vulnerability result
				vulnerabilityResult.Layers = append(vulnerabilityResult.Layers, layer)
			}

			isRelevant := vulnerabilityResult.GetIsRelevant()
			if isRelevant != nil {
				if *isRelevant {
					vulnerabilityResult.SetRelevantLabel(containerscan.RelevantLabelYes)
				} else {
					vulnerabilityResult.SetRelevantLabel(containerscan.RelevantLabelNo)
				}
			}

			vulnerabilityResults = append(vulnerabilityResults, vulnerabilityResult)
		}
		if target.IsImageTarget() {
			imageMetadata := target.GetImageMetadata()
			// parse layers from payload
			data, err := parseLayersPayload(*imageMetadata)
			if err != nil {
				return vulnerabilityResults, err
			}

			// fill extra layer information
			for i, v := range vulnerabilityResults {
				// The package is introduced by the earliest layer it appears in. This used to
				// walk the parent chain from "", which meant it only ever resolved for a
				// package present in the image's first layer: for anything added by a later
				// layer no element could start the chain, and the result stayed empty.
				earlyLayer := ""
				earlyPosition := 0
				for j, layer := range v.Layers {
					if position, ok := layerPosition[layer.LayerHash]; ok && (earlyLayer == "" || position < earlyPosition) {
						earlyLayer, earlyPosition = layer.LayerHash, position
					}
					if l, ok := data[layer.LayerHash]; ok {
						if layer.LayerInfo == nil {
							vulnerabilityResults[i].Layers[j].LayerInfo = &containerscan.LayerInfo{}
						}
						vulnerabilityResults[i].Layers[j].CreatedBy = l.CreatedBy
						vulnerabilityResults[i].Layers[j].CreatedTime = l.CreatedTime
						vulnerabilityResults[i].Layers[j].LayerOrder = l.LayerOrder
					}
				}
				if earlyLayer == "" && len(v.Layers) > 0 {
					// No layer of this package is one of the image's own, which is the case
					// for a match with no locations: it is given the placeholder layer above.
					earlyLayer = v.Layers[0].LayerHash
				}
				vulnerabilityResults[i].IntroducedInLayer = earlyLayer
			}
		}
	}

	return vulnerabilityResults, nil
}

func linkToVuln(id string) string {
	switch {
	case strings.HasPrefix(id, "EUVD-"):
		return "https://euvd.enisa.europa.eu/enisa/" + id

	case strings.HasPrefix(id, "GHSA-"):
		return "https://github.com/advisories/" + id

	case strings.HasPrefix(id, "RHSA-"):
		return "https://access.redhat.com/errata/" + id

	case strings.HasPrefix(id, "USN-"):
		return "https://ubuntu.com/security/notices/" + id + "/"

	case strings.HasPrefix(id, "DSA-"):
		return "https://security-tracker.debian.org/tracker/" + id

	case strings.HasPrefix(id, "ELSA-"):
		return "https://linux.oracle.com/errata/" + id + ".html"

	case strings.HasPrefix(id, "RLSA-"):
		return "https://errata.rockylinux.org/" + id

	case strings.HasPrefix(id, "ALAS2023-"):
		return "https://alas.aws.amazon.com/AL2023/ALAS-" +
			strings.TrimPrefix(id, "ALAS2023-") + ".html"

	case strings.HasPrefix(id, "ALAS2-"):
		return "https://alas.aws.amazon.com/AL2/ALAS-" +
			strings.TrimPrefix(id, "ALAS2-") + ".html"

	case strings.HasPrefix(id, "ALAS-"):
		return "https://alas.aws.amazon.com/" + id + ".html"

	default:
		return "https://nvd.nist.gov/vuln/detail/" + id
	}
}

// suggestedVersion returns the nearest version in versions that fixes current: the
// smallest one strictly greater than current. versions is not guaranteed to be sorted
// (it comes straight from the upstream vulnerability feed, which may list fix versions
// for several maintained branches in any order), so the whole slice must be scanned
// rather than trusting the first qualifying entry.
//
// artifactType selects how versions are compared: for every ecosystem where Grype
// itself defines a format-aware comparator distinct from semver - apk, deb, rpm (e.g.
// an epoch-prefixed "1:2.3.4-1", or an Alpine "-r10" release revision), Maven, Python
// (PEP 440), RubyGems, Portage, Go modules, Windows KB and Bitnami - versions are
// compared with that same comparator instead, the one Grype's own presenter uses to
// sort fix versions (models.NewVulnerability, via sortVersions). Generic semver
// comparison below is otherwise unchanged for every other ecosystem (npm, NuGet, and
// the other ecosystems that are already semver or close enough to it).
//
// If current is not a version in the chosen comparator, the first entry is returned,
// since there is nothing to compare against. If current is a version but no entry in
// versions is greater than it, "" is returned rather than falling back to versions[0];
// versions[0] could be older than current, which would suggest a downgrade (#844).
//
// For a recognized ecosystem, current failing to parse under its own comparator never
// falls through to the semver path below: semver was never meant to parse that
// ecosystem's versions either, and guessing versions[0] through it would reintroduce
// the same unproven-remediation problem this function exists to avoid, just one layer
// removed.
func suggestedVersion(current string, versions []string, artifactType v1beta1.SyftType) string {
	if len(versions) == 0 {
		return ""
	}

	if format, ok := versionFormatForArtifact(artifactType); ok {
		return nearestDistroFix(current, versions, format)
	}

	c, err := semver.NewVersion(current)
	if err != nil {
		return versions[0]
	}

	var nearest *semver.Version
	var nearestStr string
	for _, version := range versions {
		v, err := semver.NewVersion(version)
		if err != nil {
			continue
		}
		if !c.LessThan(v) {
			continue
		}
		if nearest == nil || v.LessThan(nearest) {
			nearest = v
			nearestStr = version
		}
	}
	return nearestStr
}

// versionFormatForArtifact reports the Grype version format matching the ecosystem of
// the artifact a match was found in, for every ecosystem where Grype defines a
// format-aware comparator distinct from generic semver. Every other ecosystem returns
// false and keeps using suggestedVersion's semver comparison.
//
// This maps directly from the syft package type on the artifact (see
// github.com/anchore/syft/syft/pkg.Type), mirroring how Grype's own
// grype/pkg.VersionFormat resolves a match's comparator, rather than routing
// artifactType through grypeversion.ParseFormat. ParseFormat matches format *names*
// ("maven", "go", "kb"), but several syft package types are spelled differently from
// Grype's own format name for that ecosystem - "java-archive", "go-module", "msrc-kb" -
// so a name-based lookup silently misses them and falls through to the unguarded
// semver comparison this function exists to avoid (#960).
//
// JVM installations (Grype's JVMFormat) are a metadata-based sub-case of the same
// java-archive syft type used for ordinary Java library dependencies, distinguished by
// package metadata that isn't carried on v1beta1.GrypePackage; java-archive is mapped
// to MavenFormat unconditionally here, which is Grype's own format for the vast
// majority of java-archive matches.
func versionFormatForArtifact(artifactType v1beta1.SyftType) (grypeversion.Format, bool) {
	switch syftPkg.Type(artifactType) {
	case syftPkg.ApkPkg:
		return grypeversion.ApkFormat, true
	case syftPkg.DebPkg:
		return grypeversion.DebFormat, true
	case syftPkg.RpmPkg:
		return grypeversion.RpmFormat, true
	case syftPkg.JavaPkg:
		return grypeversion.MavenFormat, true
	case syftPkg.PythonPkg:
		return grypeversion.PythonFormat, true
	case syftPkg.GemPkg:
		return grypeversion.GemFormat, true
	case syftPkg.PortagePkg:
		return grypeversion.PortageFormat, true
	case syftPkg.GoModulePkg:
		return grypeversion.GolangFormat, true
	case syftPkg.KbPkg:
		return grypeversion.KBFormat, true
	case syftPkg.BitnamiPkg:
		return grypeversion.BitnamiFormat, true
	default:
		return grypeversion.UnknownFormat, false
	}
}

// nearestDistroFix returns the smallest version in versions that is strictly greater
// than current, comparing both under format instead of generic semver. "" is returned
// both when current itself fails to parse under format (nothing to compare against) and
// when no candidate qualifies; a candidate that fails to parse, or that rpmSafeToCompare
// rejects, is simply skipped rather than treated as disqualifying the whole result.
func nearestDistroFix(current string, versions []string, format grypeversion.Format) string {
	c := grypeversion.New(current, format)
	if err := c.Validate(); err != nil {
		return ""
	}

	var nearest *grypeversion.Version
	var nearestStr string
	for _, raw := range versions {
		if format == grypeversion.RpmFormat && !rpmSafeToCompare(current, raw) {
			continue
		}
		v := grypeversion.New(raw, format)
		cmp, err := c.Compare(v)
		if err != nil || cmp >= 0 {
			continue
		}
		if nearest == nil {
			nearest, nearestStr = v, raw
			continue
		}
		if format == grypeversion.RpmFormat && !rpmSafeToCompare(nearestStr, raw) {
			continue
		}
		if nc, err := nearest.Compare(v); err == nil && nc > 0 {
			nearest, nearestStr = v, raw
		}
	}
	return nearestStr
}

// rpmSafeToCompare reports whether a and b can be safely ordered by Grype's RPM
// comparator (github.com/anchore/grype/grype/version, rpmVersion.compare). That
// comparator is a deliberately pragmatic vulnerability-matching tool, not a spec-compliant
// one, and its shortcuts can turn "not proven to be an upgrade" into "accepted as one":
//
//  1. It only compares epochs when both sides carry one explicitly, skipping the
//     comparison entirely otherwise -- rather than treating a missing epoch as 0, which is
//     what RPM itself specifies. A current version with an explicit higher epoch (e.g.
//     "1:0") can therefore be judged older than a candidate that merely omits its epoch
//     (e.g. "1"), when the candidate is actually the same release or older.
//  2. Its tokenizer has no notion of "^" (RPM's post-release/snapshot marker) at all: the
//     caret is silently dropped and the digits around it are compared as an ordinary
//     numeric segment, which can rank a caret-tagged snapshot above the release that
//     actually supersedes it (e.g. "1.0^20250611" over "1.0.1").
//  3. When one version string tokenizes into strictly more alphanumeric segments than the
//     other and every extra segment is literally "0", it treats the two versions as equal
//     and falls through to comparing releases alone -- rather than what real RPM/librpm
//     does, which is to treat the version with the extra segment as newer regardless of
//     release. "1.0-1" therefore outranks "1-2" under real RPM (the release never even
//     gets compared), but Grype calls "1-2" the upgrade.
//
// Reimplementing spec-compliant RPM version comparison here would trade one hazard for
// another -- a hand-rolled comparator error would be just as capable of shipping a wrong
// remediation. Since suggestedVersion's contract is "never suggest an unproven upgrade,"
// the conservative answer for any of these shapes is to treat the pair as impossible to
// order safely, so the caller skips that candidate rather than trusting Grype's relaxed
// result.
func rpmSafeToCompare(a, b string) bool {
	if strings.Contains(a, "^") || strings.Contains(b, "^") {
		return false
	}
	if rpmHasExplicitEpoch(a) != rpmHasExplicitEpoch(b) {
		return false
	}
	return !rpmVersionsDifferOnlyByTrailingZeros(rpmVersionPart(a), rpmVersionPart(b))
}

// rpmHasExplicitEpoch reports whether raw carries an "epoch:" prefix, mirroring how
// Grype's own rpmVersion parser (splitEpochFromVersion) detects one: split once on ":"
// and treat a first field present as the epoch.
func rpmHasExplicitEpoch(raw string) bool {
	return strings.Contains(raw, ":")
}

// rpmVersionPart returns raw's version component alone -- without any epoch prefix or
// release suffix -- mirroring how Grype's own rpmVersion parser (newRpmVersion) splits
// one: strip "epoch:" if present, then take everything before the first "-".
func rpmVersionPart(raw string) string {
	if _, after, ok := strings.Cut(raw, ":"); ok {
		raw = after
	}
	version, _, _ := strings.Cut(raw, "-")
	return version
}

// rpmAlnumSegment matches the same three token kinds Grype's own RPM version comparator
// tokenizes a version string into (github.com/anchore/grype/grype/version, alphanumPattern):
// a run of letters, a run of digits, or a literal "~". Everything else (".", "+", etc.) is a
// separator and is dropped, exactly as Grype's own FindAllString-based tokenizing drops it.
var rpmAlnumSegment = regexp.MustCompile(`[a-zA-Z]+|[0-9]+|~`)

// rpmVersionsDifferOnlyByTrailingZeros reports whether a and b tokenize (by
// rpmAlnumSegment) to a common prefix followed by one side having extra segments that are
// all zero-valued -- the shape Grype's compareRpmVersions treats as "equal" instead of
// "the side with the extra segment is newer." Both the prefix comparison and the
// all-zero check are numeric-aware (leading zeros trimmed before comparing digit runs),
// matching Grype's own segment comparison: a prefix pair Grype would judge numerically
// equal (e.g. "01" and "1") must be recognized as equal here too, or this shape slips
// past rpmSafeToCompare's guard as a false negative -- the opposite of "skip when
// unsure" (#961).
func rpmVersionsDifferOnlyByTrailingZeros(a, b string) bool {
	segsA := rpmAlnumSegment.FindAllString(a, -1)
	segsB := rpmAlnumSegment.FindAllString(b, -1)
	if len(segsA) == len(segsB) {
		return false
	}
	shorter, longer := segsA, segsB
	if len(shorter) > len(longer) {
		shorter, longer = longer, shorter
	}
	for i := range shorter {
		if !rpmSegmentsEqual(shorter[i], longer[i]) {
			return false
		}
	}
	for _, seg := range longer[len(shorter):] {
		if !rpmSegmentIsZero(seg) {
			return false
		}
	}
	return true
}

// rpmSegmentsEqual reports whether a and b are the same rpmAlnumSegment token. Digit
// runs are compared numerically (leading zeros trimmed), since Grype's own tokenizer
// does the same; a letter run or "~" has no notion of a leading zero and is compared as
// a plain string.
func rpmSegmentsEqual(a, b string) bool {
	na, aIsDigits := trimLeadingZeros(a)
	nb, bIsDigits := trimLeadingZeros(b)
	if aIsDigits && bIsDigits {
		return na == nb
	}
	return a == b
}

// rpmSegmentIsZero reports whether seg is a digit run whose numeric value is zero (e.g.
// "0" or "00"). A letter run or "~" is never zero-valued.
func rpmSegmentIsZero(seg string) bool {
	trimmed, isDigits := trimLeadingZeros(seg)
	return isDigits && trimmed == "0"
}

// trimLeadingZeros reports s with its leading zeros stripped (leaving a single "0" for
// an all-zero run), along with whether s is a run of digits at all. A non-digit s (a
// letter run, or "~") is returned unchanged with ok false.
func trimLeadingZeros(s string) (trimmed string, ok bool) {
	for _, r := range s {
		if r < '0' || r > '9' {
			return s, false
		}
	}
	trimmed = strings.TrimLeft(s, "0")
	if trimmed == "" {
		trimmed = "0"
	}
	return trimmed, true
}

func parseLayersPayload(target source.ImageMetadata) (map[string]containerscan.ESLayer, error) {
	layerMap := make(map[string]containerscan.ESLayer)
	if target.RawConfig == nil {
		return layerMap, nil
	}

	jsonConfig := &v1.ConfigFile{}
	err := json.Unmarshal(target.RawConfig, jsonConfig)
	if err != nil {
		return nil, err
	}

	listLayers := make([]containerscan.ESLayer, 0)
	// Retain full build-step orders while pairing only physical layers with DiffIDs.
	for i := range jsonConfig.History {

		if !jsonConfig.History[i].EmptyLayer {
			listLayers = append(listLayers, containerscan.ESLayer{LayerInfo: &containerscan.LayerInfo{
				CreatedBy:   jsonConfig.History[i].CreatedBy,
				CreatedTime: &jsonConfig.History[i].Created.Time,
				LayerOrder:  i,
			},
			})
		}
	}
	for i := 0; i < len(listLayers) && i < len(jsonConfig.RootFS.DiffIDs); i++ {
		listLayers[i].LayerHash = jsonConfig.RootFS.DiffIDs[i].String()
		if i > 0 {
			listLayers[i].ParentLayerHash = jsonConfig.RootFS.DiffIDs[i-1].String()
		}
		layerMap[listLayers[i].LayerHash] = listLayers[i]
	}

	return layerMap, nil
}

func syftCoordinatesToCoordinates(c []v1beta1.SyftCoordinates) []containerscan.Coordinates {
	var coordinates []containerscan.Coordinates
	for _, v := range c {
		coordinates = append(coordinates, containerscan.Coordinates{
			RealPath:     v.RealPath,
			FileSystemID: v.FileSystemID,
		})
	}
	return coordinates

}

func ParseImageManifest(grypeDocument *v1beta1.GrypeDocument) (*containerscan.ImageManifest, error) {
	if grypeDocument == nil || grypeDocument.Source == nil {
		return nil, fmt.Errorf("empty grype document")
	}

	var rawManifest source.ImageMetadata
	if err := json.Unmarshal(grypeDocument.Source.Target, &rawManifest); err != nil {
		return nil, err
	}

	var config v1.ConfigFile
	err := json.Unmarshal(rawManifest.RawConfig, &config)
	if err != nil {
		return nil, err
	}

	imageManifest := containerscan.ImageManifest{
		Architecture: config.Architecture,
		OS:           config.OS,
		Size:         rawManifest.Size,
		Layers:       []containerscan.ESLayer{},
	}

	// Every history entry has a unique chronological order, matching parseLayersPayload.
	// Metadata-only steps consume an order but no physical layer hash or size.
	layerIndex := 0
	for order, historyLayer := range config.History {
		layerInfo := containerscan.ESLayer{
			LayerInfo: &containerscan.LayerInfo{
				CreatedBy:   historyLayer.CreatedBy,
				CreatedTime: &historyLayer.Created.Time,
				LayerOrder:  order,
			},
		}
		if !historyLayer.EmptyLayer {
			if layerIndex < len(rawManifest.Layers) {
				layerInfo.LayerHash = rawManifest.Layers[layerIndex].Digest
				layerInfo.Size = rawManifest.Layers[layerIndex].Size
			}
			layerIndex++
		}
		imageManifest.Layers = append(imageManifest.Layers, layerInfo)
	}
	return &imageManifest, nil
}
