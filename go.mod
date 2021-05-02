module ca-vuln-scan

go 1.13

replace asterix.cyberarmor.io/cyberarmor/capacketsgo => ./vendor/asterix.cyberarmor.io/cyberarmor/capacketsgo

require (
	asterix.cyberarmor.io/cyberarmor/capacketsgo v0.0.0
	github.com/quay/claircore v0.4.0
)
