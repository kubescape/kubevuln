package repositories

import (
	"maps"
	"strings"

	"github.com/kubescape/kubevuln/core/domain"
)

// Import provenance describes the payload being replaced. Merging stale provenance
// onto a freshly catalogued payload would misidentify its producer and trust policy.
func mergeInventoryAnnotations(existing, incoming map[string]string, replace bool) map[string]string {
	base := maps.Clone(existing)
	if replace {
		for key := range base {
			if strings.HasPrefix(key, domain.SBOMImportPrefix) {
				delete(base, key)
			}
		}
	}
	return mergeMaps(base, incoming)
}
