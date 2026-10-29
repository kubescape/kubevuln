package sbomreuse

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// boundedTransport applies limits before the registry library buffers a response.
// The shared budget includes authentication, manifests, config, referrers and blobs.
type boundedTransport struct {
	base      http.RoundTripper
	maxBody   int64
	mu        sync.Mutex
	remaining int64
	requests  int
	bytes     int64
}

func (t *boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// The registry library has a legacy tag fallback; this profile deliberately
	// requires OCI referrers discovery instead of accepting attachment conventions.
	if strings.Contains(req.URL.Path, "/manifests/sha256-") {
		return nil, fmt.Errorf("registry does not support OCI referrers")
	}
	t.mu.Lock()
	t.requests++
	exhausted := t.requests > 64 || t.remaining <= 0
	t.mu.Unlock()
	if exhausted {
		return nil, fmt.Errorf("SBOM registry request budget exhausted")
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Never accept a truncated referrers listing as an unambiguous candidate set.
	if resp.Header.Get("Link") != "" {
		return nil, fmt.Errorf("paginated registry responses are unsupported")
	}
	if resp.ContentLength > t.maxBody {
		return nil, fmt.Errorf("SBOM registry response exceeds size limit")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, t.maxBody+1))
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.bytes += int64(len(b))
	t.remaining -= int64(len(b))
	exhausted = t.remaining < 0
	t.mu.Unlock()
	if int64(len(b)) > t.maxBody || exhausted {
		return nil, fmt.Errorf("SBOM registry response exceeds size budget")
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return resp, nil
}

func (t *boundedTransport) fetchedBytes() int64 { t.mu.Lock(); defer t.mu.Unlock(); return t.bytes }
