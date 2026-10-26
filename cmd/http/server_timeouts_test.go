package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The scan API server bounds how long a request may take to arrive and to be answered,
// so a client that drips a body or never reads the response cannot hold a connection open.
func TestScanServerBoundsRequests(t *testing.T) {
	srv := scanServer(http.NotFoundHandler())
	assert.Equal(t, ":8080", srv.Addr)
	assert.Equal(t, 10*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 30*time.Second, srv.ReadTimeout)
	assert.Equal(t, 30*time.Second, srv.WriteTimeout)
	assert.Equal(t, 120*time.Second, srv.IdleTimeout)
}
