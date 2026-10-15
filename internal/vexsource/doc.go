// Package vexsource provides ingestion of external VEX sources.
//
// Source.Fetch retrieves and validates an external VEX document. OpenVEX is
// the default format for backward compatibility; CSAF can be selected
// explicitly. BatchDocument stages a validated document for Grype consumption.
// The VEXSource controller described in issue #387 is responsible for calling
// this package and persisting the validated document.
package vexsource
