// Package syftmeta carries the one step that has to happen after a Syft SBOM is round-tripped
// through JSON into the storage types: putting each package's metadata back.
package syftmeta

import (
	"encoding/json"

	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// Reattach copies MetadataType and Metadata from the Syft document onto the matching stored
// packages, which the JSON round-trip that produced them drops: v1beta1.SyftPackage holds
// Metadata as a json.RawMessage, so it does not survive being decoded into a typed field.
//
// Both SBOM paths need it, the in-process SyftAdapter and the sidecar scanner's gRPC server,
// and they had a copy each. Keeping one copy is worth a shared package here: three separate
// bugs (#585, #587, #601) have come from those two paths drifting apart.
//
// Indexed by ID rather than scanned: an SBOM has a package per artifact, so pairing them by
// searching the whole document for each one is quadratic, and at a few thousand packages,
// ordinary for a Java or Node image, that is most of the time this conversion takes. On a
// duplicate ID the first Syft package wins, matching the search this replaces.
func Reattach(stored []v1beta1.SyftPackage, doc []model.Package) {
	if len(stored) == 0 || len(doc) == 0 {
		return
	}

	byID := make(map[string]*model.Package, len(doc))
	for i := range doc {
		if _, seen := byID[doc[i].ID]; !seen {
			byID[doc[i].ID] = &doc[i]
		}
	}

	for i := range stored {
		p, ok := byID[stored[i].ID]
		if !ok {
			continue
		}
		stored[i].MetadataType = p.MetadataType
		b, err := json.Marshal(p.Metadata)
		if err != nil {
			logger.L().Warning("failed to marshal Syft package metadata",
				helpers.Error(err), helpers.String("packageID", p.ID))
			continue
		}
		stored[i].Metadata = b
	}
}
