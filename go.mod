module ca-vuln-scan

go 1.15

require (
	github.com/armosec/armoapi-go v0.0.53
	github.com/armosec/cluster-container-scanner-api v0.0.19
	github.com/armosec/logger-go v0.0.4
	github.com/armosec/utils-k8s-go v0.0.2
	github.com/docker/docker v20.10.9+incompatible
	github.com/golang/glog v1.0.0
	github.com/xyproto/randomstring v0.0.0-20211020123341-4731a123782f
	golang.org/x/net v0.0.0-20211015210444-4f30a5c0130f // indirect
	golang.org/x/text v0.3.7 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	k8s.io/utils v0.0.0-20210819203725-bdf08cb9a70a
)
