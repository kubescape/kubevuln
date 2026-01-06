package v1

import (
	"path"

	"github.com/adrg/xdg"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
)

func NewGrypeAdapterLocal() *GrypeAdapter {
	g := &GrypeAdapter{
		distCfg: distribution.Config{
			LatestURL: "http://localhost:8000/listing.json",
		},
		installCfg: installation.Config{
			DBRootDir: path.Join(xdg.CacheHome, "grype-light", "db"),
		},
	}
	return g
}
