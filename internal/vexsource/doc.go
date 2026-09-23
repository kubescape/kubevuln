// Package vexsource provides ingestion of external VEX sources.
//
// Source.Fetch retrieves and validates an external VEX document. The
// VEXSource controller described in issue #387 is responsible for calling
// this package and persisting the validated document. Temporary-file
// creation for Grype consumption remains outside this package.
package vexsource
