package safefetch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckIPAllowed(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"loopback IPv4", "127.0.0.1", true},
		{"loopback IPv6", "::1", true},
		{"link-local IPv4 (cloud metadata range)", "169.254.169.254", true},
		{"link-local IPv6", "fe80::1", true},
		{"private RFC1918 class A", "10.0.0.1", true},
		{"private RFC1918 class B", "172.16.0.1", true},
		{"private RFC1918 class C", "192.168.1.1", true},
		{"IPv6 unique local", "fc00::1", true},
		{"unspecified IPv4", "0.0.0.0", true},
		{"unspecified IPv6", "::", true},
		{"multicast", "224.0.0.1", true},
		{"real public IPv4 (Google DNS)", "8.8.8.8", false},
		{"real public IPv4 (Cloudflare DNS)", "1.1.1.1", false},
		{"carrier-grade NAT / cloud internal (100.64.0.0/10)", "100.64.0.1", true},
		{"0.0.0.0/8 (routes to localhost on Linux)", "0.0.0.1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "test IP %q failed to parse", tt.ip)
			err := checkIPAllowed(ip)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrBlockedIP)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFetch_RejectsNonHTTPS(t *testing.T) {
	f := New()
	tests := []string{
		"http://example.com/feed.json",
		"ftp://example.com/feed.json",
		"file:///etc/passwd",
	}
	for _, u := range tests {
		t.Run(u, func(t *testing.T) {
			_, err := f.Fetch(context.Background(), u)
			assert.ErrorIs(t, err, ErrScheme)
		})
	}
}

func TestFetch_MalformedURL(t *testing.T) {
	f := New()
	_, err := f.Fetch(context.Background(), "://not-a-url")
	assert.Error(t, err)
}

func TestFetch_WithoutClient(t *testing.T) {
	f := Fetcher{}
	_, err := f.Fetch(context.Background(), "https://example.com")
	assert.ErrorIs(t, err, ErrNoClient)
}

// TestFetch_BlocksRealLoopbackServer is the key end-to-end proof: it spins
// up a real, working HTTPS server (so this is not a theoretical IP check,
// it is a genuinely reachable server that would happily respond), and
// confirms our own Fetch refuses to talk to it, because the server listens
// on loopback - simulating exactly the SSRF scenario where an attacker
// points a VEXSource.url at an internal address.
func TestFetch_BlocksRealLoopbackServer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"secret": "you should never see this"}`)
	}))
	defer server.Close()

	f := New()
	// The test server's own TLS cert isn't trusted by the default client,
	// but that's irrelevant here: our dial-time IP check must reject the
	// connection before TLS verification is ever reached.
	body, err := f.Fetch(context.Background(), server.URL)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBlockedIP)
	assert.Nil(t, body)
}

func TestFetch_RejectsOversizedBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 100))
	}))
	defer server.Close()

	// Use the TLS test server's own client (which trusts its self-signed
	// cert) instead of New()'s SSRF-guarded client, since the server
	// necessarily listens on loopback, which SafeFetch correctly refuses
	// to dial (covered separately by TestFetch_BlocksRealLoopbackServer).
	// This still exercises Fetch's real logic end-to-end: scheme
	// validation, request execution, and MaxBytes/ErrTooLarge
	// enforcement, via an actual https:// call to Fetch itself.
	f := &Fetcher{Client: server.Client(), MaxBytes: 10}

	body, err := f.Fetch(context.Background(), server.URL)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTooLarge)
	assert.Nil(t, body)
}

func TestErrorsAreDistinguishable(t *testing.T) {
	// Sanity check that each sentinel error is genuinely distinct, so
	// callers relying on errors.Is get meaningful results.
	all := []error{ErrScheme, ErrBlockedIP, ErrTooManyRedirects, ErrTooLarge, ErrStatus, ErrNoClient}
	for i, a := range all {
		for j, b := range all {
			if i == j {
				continue
			}
			assert.False(t, errors.Is(a, b), "%v should not match %v", a, b)
		}
	}
}

// An IPv6 address can carry an IPv4 one inside it, and the packet is delivered to that
// IPv4 destination. net.IP.To4 unwraps only the IPv4-mapped form, so for the rest the
// checks in checkIPAllowed saw an ordinary global-unicast IPv6 address and allowed it.
// On an IPv6-only cluster running DNS64/NAT64, an ordinary Kubernetes setup, that meant
// 64:ff9b::a9fe:a9fe reached 169.254.169.254, the endpoint this package exists to block.
func TestCheckIPAllowed_EmbeddedIPv4(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"NAT64 well-known to cloud metadata", "64:ff9b::a9fe:a9fe", true},
		{"NAT64 well-known to RFC1918", "64:ff9b::a00:1", true},
		{"NAT64 well-known to loopback", "64:ff9b::7f00:1", true},
		{"NAT64 local-use prefix (RFC 8215)", "64:ff9b:1::a9fe:a9fe", true},
		{"6to4 to cloud metadata", "2002:a9fe:a9fe::", true},
		{"IPv4-compatible to cloud metadata", "::a9fe:a9fe", true},
		{"IPv4-translated to cloud metadata", "::ffff:0:a9fe:a9fe", true},
		{"IPv4-mapped to loopback", "::ffff:127.0.0.1", true},

		// the embedded address is what decides it, so translation to a genuinely
		// public host stays reachable: on an IPv6-only cluster NAT64 is how it is
		// reached at all.
		{"NAT64 well-known to public IPv4", "64:ff9b::808:808", false},
		{"6to4 to public IPv4", "2002:808:808::", false},
		{"ordinary public IPv6", "2606:4700:4700::1111", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "test IP %q failed to parse", tt.ip)
			err := checkIPAllowed(ip)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrBlockedIP)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
