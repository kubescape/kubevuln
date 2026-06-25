package main

import (
	"database/sql"
	"testing"
)

// TestSqliteDriverRegistered guards against a regression of
// https://github.com/kubescape/kubevuln/issues/378: Syft's RPM (redhat)
// cataloger requires a sqlite driver registered under the name "sqlite" to read
// newer sqlite-backed RPM databases. The sidecar does not import grype (which
// would otherwise pull one transitively), so it must register one itself via a
// blank import in main.go.
func TestSqliteDriverRegistered(t *testing.T) {
	var count int
	for _, d := range sql.Drivers() {
		if d == "sqlite" {
			count++
		}
	}
	if count == 0 {
		t.Fatalf(`no sqlite driver registered; Syft's RPM cataloger needs sql.Open("sqlite", ...) to work`)
	}
	if count > 1 {
		t.Fatalf("sqlite driver registered %d times; risk of \"Register called twice\" panic", count)
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(sqlite): %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping in-memory sqlite: %v", err)
	}
}
