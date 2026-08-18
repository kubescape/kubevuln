// Package safefetch provides an HTTP client for fetching arbitrary,
// user-controlled URLs safely, guarding against SSRF (Server-Side Request
// Forgery). It is not wired into any specific feature; it exists as a
// reusable primitive for any future code path (such as VEXSource
// ingestion, kubevuln#387) that needs to fetch a URL a user supplied,
// rather than a fixed, trusted endpoint.
package safefetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// carrierGradeNAT is RFC 6598's shared address space (100.64.0.0/10),
// used inside cloud provider and Kubernetes internal networks (AWS CNI,
// GCP, Tailscale, pod CIDRs). net.IP.IsPrivate() does not cover this
// range, so it must be checked explicitly.
var carrierGradeNAT = mustParseCIDR("100.64.0.0/10")

// thisHostOnThisNetwork is RFC 1122's 0.0.0.0/8. Every address in this
// range other than 0.0.0.0 itself is non-zero, so it passes
// IsUnspecified(), and none of it is covered by IsLoopback() or
// IsPrivate() - but on Linux, dialing any address in this range
// (e.g. 0.0.0.1) actually connects to 127.0.0.1 (localhost), making it a
// working bypass of the loopback check if left unhandled.
var thisHostOnThisNetwork = mustParseCIDR("0.0.0.0/8")

// The IPv6 transition mechanisms below each carry an IPv4 address inside an IPv6 one,
// and a packet sent to them is delivered to that IPv4 destination. net.IP.To4 unwraps
// only the IPv4-mapped form (::ffff:a.b.c.d), so for these the checks in checkIPAllowed
// see an ordinary global-unicast IPv6 address, match none of them, and allow it: on an
// IPv6-only cluster running DNS64/NAT64, which is an ordinary Kubernetes setup,
// 64:ff9b::a9fe:a9fe reaches 169.254.169.254.
//
// The embedded address is extracted and checked rather than the prefix being rejected
// outright, because on such a cluster NAT64 is also how a legitimate public IPv4 host is
// reached, and blocking the prefix would block those too.
var (
	// nat64WellKnown is RFC 6052's well-known prefix, which carries the IPv4 address
	// in its low 32 bits.
	nat64WellKnown = mustParseCIDR("64:ff9b::/96")
	// nat64LocalUse is RFC 8215's local-use prefix. RFC 6052 splits the IPv4 address
	// around the u octet for prefixes shorter than /96, so rather than reassemble it
	// this is refused outright: it is a network-specific translation prefix, not
	// somewhere a public feed is published.
	nat64LocalUse = mustParseCIDR("64:ff9b:1::/48")
	// sixToFour is RFC 3056's 6to4 prefix, which carries the IPv4 address in the two
	// groups after the prefix rather than in the low 32 bits.
	sixToFour = mustParseCIDR("2002::/16")
	// ipv4Compatible is the ::a.b.c.d form deprecated by RFC 4291, and ipv4Translated
	// the ::ffff:0:a.b.c.d form from RFC 2765. Both carry the address in the low 32
	// bits, and neither is unwrapped by To4.
	ipv4Compatible = mustParseCIDR("::/96")
	ipv4Translated = mustParseCIDR("::ffff:0:0:0/96")
)

// embeddedIPv4 returns the IPv4 address an IPv6 transition mechanism carries inside ip,
// or nil when ip carries none. It reports nothing for addresses To4 already unwraps,
// since checkIPAllowed's own checks cover those.
func embeddedIPv4(ip net.IP) net.IP {
	if ip.To4() != nil {
		return nil
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil
	}
	switch {
	case sixToFour.Contains(ip16):
		return net.IPv4(ip16[2], ip16[3], ip16[4], ip16[5])
	case nat64WellKnown.Contains(ip16), ipv4Compatible.Contains(ip16), ipv4Translated.Contains(ip16):
		return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
	}
	return nil
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

var (
	// ErrScheme is returned when a URL is not https.
	ErrScheme = errors.New("only https URLs are allowed")
	// ErrBlockedIP is returned when a URL resolves to a private, loopback,
	// link-local, or otherwise non-routable IP address.
	ErrBlockedIP = errors.New("target address is not allowed")
	// ErrTooManyRedirects is returned when a fetch follows more redirects
	// than allowed.
	ErrTooManyRedirects = errors.New("too many redirects")
	// ErrTooLarge is returned when a response body exceeds MaxBytes.
	ErrTooLarge = errors.New("response body exceeds maximum size")
	// ErrStatus is returned when the server responds with a non-2xx status.
	ErrStatus = errors.New("unexpected response status")
	// ErrNoClient is returned when a Fetcher is used without being built
	// via New, so it has no underlying HTTP client.
	ErrNoClient = errors.New("fetcher has no http client")
)

const (
	defaultTimeout      = 10 * time.Second
	defaultDialTimeout  = 5 * time.Second
	defaultMaxBytes     = 10 << 20 // 10 MiB
	defaultMaxRedirects = 5
)

// Fetcher retrieves a URL over HTTPS, rejecting private, loopback, and
// link-local destinations (including cloud metadata endpoints such as
// 169.254.169.254) both for the initial request and for every redirect
// hop. IP validation happens at actual connection time via a custom
// DialContext, not just when the URL is first parsed, so a DNS record
// that changes between the check and the connection (DNS rebinding)
// cannot bypass it.
type Fetcher struct {
	Client   *http.Client
	MaxBytes int64
}

// New builds a Fetcher with SSRF protections wired into its transport.
func New() *Fetcher {
	dialer := &net.Dialer{Timeout: defaultDialTimeout}

	safeDialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("splitting host/port for %q: %w", addr, err)
		}

		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", host, err)
		}

		var lastErr error
		for _, ip := range ips {
			if err := checkIPAllowed(ip); err != nil {
				lastErr = err
				continue
			}
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no addresses found for %s", host)
		}
		return nil, lastErr
	}

	return &Fetcher{
		MaxBytes: defaultMaxBytes,
		Client: &http.Client{
			Timeout: defaultTimeout,
			Transport: &http.Transport{
				DialContext: safeDialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= defaultMaxRedirects {
					return ErrTooManyRedirects
				}
				if req.URL.Scheme != "https" {
					return fmt.Errorf("redirect target: %w", ErrScheme)
				}
				return nil
			},
		},
	}
}

// checkIPAllowed reports an error if ip is loopback, link-local (unicast
// or multicast; this range includes cloud metadata endpoints such as
// 169.254.169.254), private (RFC 1918 for IPv4, the IPv6 unique local
// range), unspecified, or multicast.
func checkIPAllowed(ip net.IP) error {
	if ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		carrierGradeNAT.Contains(ip) ||
		thisHostOnThisNetwork.Contains(ip) ||
		nat64LocalUse.Contains(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedIP, ip)
	}
	// An IPv6 address can carry an IPv4 one that the checks above cannot see; what the
	// packet reaches is that address, so it is what has to be allowed.
	if v4 := embeddedIPv4(ip); v4 != nil {
		if err := checkIPAllowed(v4); err != nil {
			return fmt.Errorf("%w: %s embeds %s", ErrBlockedIP, ip, v4)
		}
	}
	return nil
}

// Fetch retrieves rawURL and returns its body. rawURL must use the https
// scheme; the destination (and every redirect target) must not resolve to
// a blocked IP range.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	if f.Client == nil {
		return nil, ErrNoClient
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing url: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, ErrScheme
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%w: %s returned %s", ErrStatus, rawURL, resp.Status)
	}

	maxBytes := f.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}

	// Read one byte past the limit so an oversized body is detected
	// rather than silently truncated into whatever the caller does next.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, rawURL, maxBytes)
	}

	return body, nil
}
