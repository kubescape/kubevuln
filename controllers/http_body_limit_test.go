package controllers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gammazero/workerpool"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/kubevuln/core/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A scan request's body is bounded before it is decoded: an oversized one is refused with
// 413 without reaching the scan service, and one within the bound is handled as before.
func TestHTTPController_RejectsABodyOverTheLimit(t *testing.T) {
	c := HTTPController{scanService: services.NewMockScanService(true), workerPool: workerpool.New(1)}
	router := gin.New()
	router.POST("/v1/generateSBOM", c.GenerateSBOM)
	router.POST("/v1/scanRegistryImage", c.ScanRegistry)
	router.POST("/v1/scanImage", c.ScanCVE)
	router.POST("/v1/scanApplicationProfile", c.ScanCP)

	padding := strings.Repeat("a", maxScanCommandBytes)
	oversized := []byte(`{"imageTag":"nginx:latest","args":{"pad":"` + padding + `"}}`)
	for _, path := range []string{"/v1/generateSBOM", "/v1/scanRegistryImage", "/v1/scanImage", "/v1/scanApplicationProfile"} {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(oversized))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code, path)
	}

	small := []byte(`{"imageTag":"nginx:latest","args":{"pad":"` + strings.Repeat("a", 1024) + `"}}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/scanRegistryImage", bytes.NewReader(small))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.NotEqual(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
