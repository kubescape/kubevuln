module ca-vuln-scan

go 1.15

require (
	github.com/anchore/grype v0.34.5
	github.com/armosec/armoapi-go v0.0.63
	github.com/armosec/cluster-container-scanner-api v0.0.26
	github.com/armosec/logger-go v0.0.4
	github.com/armosec/utils-k8s-go v0.0.2
	github.com/docker/docker v20.10.12+incompatible
	github.com/golang/glog v1.0.0
	github.com/xyproto/randomstring v0.0.0-20211020123341-4731a123782f
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	k8s.io/utils v0.0.0-20220127004650-9b3446523e65
)
