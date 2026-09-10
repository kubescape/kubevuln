package v1

import (
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/vulnerability"
)

// VulnerabilityDBLoader abstracts loading the vulnerability database for GrypeAdapter.
type VulnerabilityDBLoader interface {
	LoadDB(distCfg distribution.Config, installCfg installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error)
}

// DefaultVulnerabilityDBLoader is the production implementation of VulnerabilityDBLoader using grype.LoadVulnerabilityDB.
type DefaultVulnerabilityDBLoader struct{}

var _ VulnerabilityDBLoader = DefaultVulnerabilityDBLoader{}

// LoadDB calls grype.LoadVulnerabilityDB to load the vulnerability provider.
func (DefaultVulnerabilityDBLoader) LoadDB(distCfg distribution.Config, installCfg installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
	return grype.LoadVulnerabilityDB(distCfg, installCfg, true)
}

// VulnerabilityDBLoaderFunc adapts a function to the VulnerabilityDBLoader interface.
type VulnerabilityDBLoaderFunc func(distCfg distribution.Config, installCfg installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error)

var _ VulnerabilityDBLoader = VulnerabilityDBLoaderFunc(nil)

// LoadDB calls the underlying function.
func (f VulnerabilityDBLoaderFunc) LoadDB(distCfg distribution.Config, installCfg installation.Config) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
	return f(distCfg, installCfg)
}
