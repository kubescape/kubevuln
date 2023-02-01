package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHealthCheck(t *testing.T) {
	server := NewMockServer()
	router := server.Routes()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/ready", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "{\"status\":\"UP\"}", w.Body.String())
}

func TestCreateCVE(t *testing.T) {
	tests := []struct {
		name         string
		yamlFile     string
		expectedCode int
		expectedBody string
	}{
		{
			"good",
			"../api/v1/testdata/scan.yaml",
			200,
			"{\"data\":\"new CVE scan created\",\"status\":\"success\"}",
		},
		{
			"missing fields",
			"../api/v1/testdata/scan-incomplete.yaml",
			500,
			"null",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := NewMockServer()
			router := server.Routes()

			w := httptest.NewRecorder()
			file, err := os.Open(test.yamlFile)
			assert.NoError(t, err)
			req, _ := http.NewRequest("POST", "/v1/scanImage", file)
			router.ServeHTTP(w, req)

			assert.Equal(t, test.expectedCode, w.Code)
			assert.Equal(t, test.expectedBody, w.Body.String())
		})
	}
}
