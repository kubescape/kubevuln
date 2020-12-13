package process_request

import "testing"

func TestClairScanResults(t *testing.T) {
	resultString, ferr := getClairScanResults("postgres:9.5.1")
	if ferr != nil {
		t.Errorf("scan failed: %s", ferr)
	}
	t.Logf("Result: %s", resultString)
}
