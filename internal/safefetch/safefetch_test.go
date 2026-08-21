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

// transportOf returns the SSRF-guarded transport New wired up, so the dial-time
// checks can be driven directly. Fetch reaches them only through a real connection
// attempt, which is why the guards below were previously exercised only for
// loopback and not for the rest of what checkIPAllowed refuses.
func transportOf(t *testing.T, f *Fetcher) *http.Transport {
	t.Helper()
	tr, ok := f.Client.Transport.(*http.Transport)
	require.True(t, ok, "New must install an *http.Transport")
	return tr
}

// TestNew_DialBlocksAddress is the dial-time half of the SSRF guard, and the half
// that makes DNS rebinding not work.
//
// Fetch validates nothing about the destination itself: it checks the scheme and
// hands the URL to the client. The address check happens inside DialContext,
// against the IP the resolver just returned, at the moment the connection is made.
// So a host that passes any earlier inspection and only then resolves to an internal
// address is still refused, because there is no earlier inspection to pass.
//
// "localhost" is the case that shows it: the string carries no IP, so nothing about
// the URL is refusable, and it is blocked purely on what it resolved to.
func TestNew_DialBlocksAddress(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"loopback literal", "127.0.0.1:443"},
		{"loopback IPv6 literal", "[::1]:443"},
		{"hostname resolving to loopback", "localhost:443"},
		{"cloud metadata endpoint", "169.254.169.254:80"},
		{"RFC1918 private", "10.0.0.1:443"},
		{"carrier-grade NAT", "100.64.0.1:443"},
		{"0.0.0.0/8, routes to localhost on Linux", "0.0.0.1:443"},
		{"NAT64 to cloud metadata", "[64:ff9b::a9fe:a9fe]:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New()
			conn, err := transportOf(t, f).DialContext(context.Background(), "tcp", tt.addr)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrBlockedIP)
			assert.Nil(t, conn)
		})
	}
}

func TestNew_DialRejectsAddressWithoutPort(t *testing.T) {
	f := New()
	conn, err := transportOf(t, f).DialContext(context.Background(), "tcp", "example.com")
	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "splitting host/port")
}

// TestNew_DialHonoursContextCancellation checks the dial does not outlive the caller.
// Resolution runs on the caller's context, so a cancelled one fails before any
// connection is attempted.
func TestNew_DialHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	f := New()
	conn, err := transportOf(t, f).DialContext(ctx, "tcp", "localhost:443")
	require.Error(t, err)
	assert.Nil(t, conn)
}

// TestNew_RedirectPolicy covers the other way an SSRF gets in: the first URL is a
// perfectly ordinary public https one, and the server answers with a redirect
// pointing somewhere it should not go.
//
// The scheme case matters most. Fetch refuses a non-https URL up front, but that
// check runs once, on the URL the caller passed. Without the same check on each hop,
// a public host could redirect to http:// and the request would go out in cleartext
// to whatever it named.
func TestNew_RedirectPolicy(t *testing.T) {
	// via carries the prior requests, which is what CheckRedirect counts.
	via := func(n int) []*http.Request {
		reqs := make([]*http.Request, 0, n)
		for i := 0; i < n; i++ {
			reqs = append(reqs, httptest.NewRequest(http.MethodGet, "https://example.com/", nil))
		}
		return reqs
	}

	tests := []struct {
		name    string
		target  string
		hops    int
		wantErr error
	}{
		{"https target, first hop", "https://example.com/a", 1, nil},
		{"https target, last allowed hop", "https://example.com/a", defaultMaxRedirects - 1, nil},
		{"one hop past the limit", "https://example.com/a", defaultMaxRedirects, ErrTooManyRedirects},
		{"well past the limit", "https://example.com/a", defaultMaxRedirects + 10, ErrTooManyRedirects},
		{"downgrade to http", "http://example.com/a", 1, ErrScheme},
		{"redirect to a file URL", "file:///etc/passwd", 1, ErrScheme},
		{"redirect to internal http host", "http://169.254.169.254/latest/meta-data/", 1, ErrScheme},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New()
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			err := f.Client.CheckRedirect(req, via(tt.hops))
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestNew_RedirectLimitIsCheckedBeforeScheme pins the order. A hop that is both over
// the limit and downgraded reports the limit, so a scheme downgrade cannot be used to
// mask a redirect loop.
func TestNew_RedirectLimitIsCheckedBeforeScheme(t *testing.T) {
	f := New()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/a", nil)
	over := make([]*http.Request, defaultMaxRedirects)
	for i := range over {
		over[i] = httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	}
	err := f.Client.CheckRedirect(req, over)
	assert.ErrorIs(t, err, ErrTooManyRedirects)
	assert.NotErrorIs(t, err, ErrScheme)
}

func TestNew_Defaults(t *testing.T) {
	f := New()
	require.NotNil(t, f.Client)
	assert.Equal(t, int64(defaultMaxBytes), f.MaxBytes)
	assert.Equal(t, defaultTimeout, f.Client.Timeout)
	require.NotNil(t, f.Client.CheckRedirect)
	assert.NotNil(t, transportOf(t, f).DialContext)
}

func TestFetch_RejectsNon2xxStatus(t *testing.T) {
	codes := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
	}
	for _, code := range codes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
				fmt.Fprint(w, `{"error": "body should be discarded"}`)
			}))
			defer server.Close()

			// Same reason as TestFetch_RejectsOversizedBody: the test server
			// necessarily listens on loopback, which New's dialer correctly
			// refuses, so this drives Fetch's own logic with the server's client.
			f := &Fetcher{Client: server.Client()}
			body, err := f.Fetch(context.Background(), server.URL)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrStatus)
			assert.Nil(t, body)
		})
	}
}

func TestFetch_ReturnsBody(t *testing.T) {
	const payload = `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, payload)
	}))
	defer server.Close()

	f := &Fetcher{Client: server.Client(), MaxBytes: 1 << 20}
	body, err := f.Fetch(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, payload, string(body))
}

// TestFetch_BodyExactlyAtLimit guards the boundary. Fetch reads MaxBytes+1 so an
// oversized body is caught rather than truncated, which means a body of exactly
// MaxBytes still has to be accepted whole.
func TestFetch_BodyExactlyAtLimit(t *testing.T) {
	const size = 64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", size))
	}))
	defer server.Close()

	f := &Fetcher{Client: server.Client(), MaxBytes: size}
	body, err := f.Fetch(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Len(t, body, size)

	f.MaxBytes = size - 1
	_, err = f.Fetch(context.Background(), server.URL)
	assert.ErrorIs(t, err, ErrTooLarge)
}

// TestFetch_UnsetMaxBytesUsesDefault covers a Fetcher built as a literal rather than
// by New. A zero MaxBytes has to mean the default limit, never no limit.
func TestFetch_UnsetMaxBytesUsesDefault(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "small")
	}))
	defer server.Close()

	for _, maxBytes := range []int64{0, -1} {
		f := &Fetcher{Client: server.Client(), MaxBytes: maxBytes}
		body, err := f.Fetch(context.Background(), server.URL)
		require.NoError(t, err)
		assert.Equal(t, "small", string(body))
	}
}

func TestFetch_PropagatesContextCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	f := &Fetcher{Client: server.Client()}
	_, err := f.Fetch(ctx, server.URL)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
