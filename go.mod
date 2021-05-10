module ca-vuln-scan

go 1.13

// replace asterix.cyberarmor.io/cyberarmor/capacketsgo => ./vendor/asterix.cyberarmor.io/cyberarmor/capacketsgo

require (
	github.com/armosec/capacketsgo v0.0.4
	github.com/quay/claircore v0.4.0
)
