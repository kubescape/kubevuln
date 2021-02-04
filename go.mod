module ca-vuln-scan

go 1.13

replace asterix.cyberarmor.io/cyberarmor/capacketsgo => ./vendor/asterix.cyberarmor.io/cyberarmor/capacketsgo

require (
	asterix.cyberarmor.io/cyberarmor/capacketsgo v0.0.0
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/aws/aws-sdk-go v1.36.15
	github.com/containerd/containerd v1.4.3 // indirect
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v20.10.0+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/sirupsen/logrus v1.7.0 // indirect
	google.golang.org/grpc v1.34.0 // indirect
)
