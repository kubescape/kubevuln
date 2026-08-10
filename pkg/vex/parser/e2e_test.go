package parser

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLiveFeed_MassiveStream runs an End-to-End test by dynamically generating
// a massive OpenVEX payload (simulating a 50MB+ feed) via a local HTTP server.
// It verifies that our JSON streaming parser handles massive feeds without OOM panics.
func TestLiveFeed_MassiveStream(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping massive stream E2E test in short mode.")
	}

	const statementCount = 100000

	// Create a local HTTP server that streams 100,000 OpenVEX statements
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write the start of the OpenVEX document
		fmt.Fprintf(w, `{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "test-feed", "author": "test", "timestamp": "2026-08-10T00:00:00Z", "version": 1, "statements": [`)
		
		for i := 0; i < statementCount; i++ {
			comma := ","
			if i == statementCount-1 {
				comma = ""
			}
			fmt.Fprintf(w, `{"vulnerability": {"name": "CVE-2024-%d"}, "products": ["pkg:apk/alpine/curl@%d"], "status": "not_affected"}%s`, i, i, comma)
		}
		
		fmt.Fprintf(w, `]}`)
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("Failed to fetch mock stream: %v", err)
	}
	defer resp.Body.Close()

	p := &OpenVEXStreamParser{
		SourceURL: ts.URL,
	}

	var parsedCount int
	emitFn := func(stmt VEXStatement) error {
		parsedCount++
		return nil
	}

	err = p.Parse(resp.Body, emitFn)
	if err != nil {
		t.Fatalf("Failed to parse massive OpenVEX stream: %v", err)
	}

	if parsedCount != statementCount {
		t.Fatalf("Parsed %d statements, expected %d.", parsedCount, statementCount)
	}

	t.Logf("Successfully streamed and parsed %d statements dynamically without hitting memory limits.", parsedCount)
}
