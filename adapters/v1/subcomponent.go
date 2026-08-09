package v1

import (
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	packageurl "github.com/package-url/packageurl-go"
)

// attrSubcomponents is the policy attribute carrying a vulnerability entry's PURL scope.
//
// armotypes.VulnerabilityExceptionPolicy has no field for subcomponent scoping, and it is an
// external type, so the scope travels in Attributes alongside the other provenance data
// buildSuppressionAttributes records. CRD-derived policies are built and cached in-process,
// so the value reaches ApplySecurityExceptions with its type intact.
const attrSubcomponents = "subcomponents"

// normalizedSubcomponents trims and drops empty entries, so a list that is only whitespace
// is treated as absent (product scope) rather than as a scope nothing can satisfy.
func normalizedSubcomponents(subcomponents []string) []string {
	var out []string
	for _, s := range subcomponents {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// policySubcomponents returns the PURL scope recorded on a policy and whether a scope was
// recorded at all. The two are distinct: no scope means the policy applies at product scope,
// while a scope that resolves to no usable PURL matches nothing.
//
// The value is []string for policies built in this process and []interface{} for any that
// have been through JSON, such as cloud-sourced exceptions; both are accepted so a policy
// from either source is read the same way. Any other type is still a scope, and one nothing
// can satisfy — an attribute that cannot be read as a PURL list must not widen the policy
// back to product scope.
func policySubcomponents(p armotypes.VulnerabilityExceptionPolicy) ([]string, bool) {
	raw, ok := p.Attributes[attrSubcomponents]
	if !ok {
		return nil, false
	}
	switch v := raw.(type) {
	case []string:
		return v, true
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out, true
	default:
		return nil, true
	}
}

// scopedToSubcomponent filters policies down to those that apply to the package a match was
// found in. A policy with no subcomponent scope applies at product scope and is always kept;
// a scoped policy is kept only when one of its PURLs covers purl.
func scopedToSubcomponent(policies []armotypes.VulnerabilityExceptionPolicy, purl string) []armotypes.VulnerabilityExceptionPolicy {
	var out []armotypes.VulnerabilityExceptionPolicy
	for _, p := range policies {
		subcomponents, scoped := policySubcomponents(p)
		if !scoped {
			out = append(out, p)
			continue
		}
		if anyPURLMatches(subcomponents, purl) {
			out = append(out, p)
		}
	}
	return out
}

func anyPURLMatches(subcomponents []string, purl string) bool {
	for _, s := range subcomponents {
		if purlMatches(s, purl) {
			return true
		}
	}
	return false
}

// purlMatches reports whether an exception's subcomponent PURL covers the PURL of a package a
// vulnerability was found in, following OpenVEX: an unversioned PURL matches any version of the
// package, a version-qualified PURL matches only that version.
//
// Unparseable input on either side returns false, which is the fail-closed direction: a
// malformed or missing PURL leaves the finding visible rather than silently suppressing it.
// This mirrors shouldSuppress, where anything not definitively resolved stays in the results.
func purlMatches(subcomponent, purl string) bool {
	sub, err := packageurl.FromString(subcomponent)
	if err != nil {
		return false
	}
	pkg, err := packageurl.FromString(purl)
	if err != nil {
		return false
	}
	// Type is case-insensitive per the PURL spec; namespace and name are compared as parsed,
	// since their canonical case is type-specific and FromString already applies it.
	if !strings.EqualFold(sub.Type, pkg.Type) || sub.Namespace != pkg.Namespace || sub.Name != pkg.Name {
		return false
	}
	if sub.Version != "" && sub.Version != pkg.Version {
		return false
	}
	// Qualifiers are what separate variants of the same package — arch and distro both
	// appear on scanned PURLs — so every qualifier the exception states must hold. Ones it
	// leaves out are unconstrained, keeping an unqualified PURL a match for any variant.
	pkgQualifiers := pkg.Qualifiers.Map()
	for key, want := range sub.Qualifiers.Map() {
		if pkgQualifiers[key] != want {
			return false
		}
	}
	return true
}
