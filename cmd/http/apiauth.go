package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/armosec/armoapi-go/apis"
	"github.com/gin-gonic/gin"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/storage/pkg/apiauth"
	"k8s.io/client-go/kubernetes"
)

const (
	apiGroup    = "kubescape.io"
	apiResource = "vulnerabilityscans"
)

// apiAuthRoute maps a request to the permission it needs, by path only. Probes and
// metrics are open; every other path under /v1/ is protected (fail closed).
func apiAuthRoute(r *http.Request) (apiauth.Attributes, bool) {
	p := r.URL.Path
	v1 := "/" + apis.VulnerabilityScanCommandVersion + "/"
	switch p {
	case "/metrics", v1 + "liveness", v1 + "readiness":
		return apiauth.Attributes{}, false
	case v1 + apis.ContainerScanCommandPath,
		v1 + apis.RegistryScanCommandPath,
		v1 + apis.ApplicationProfileScanCommandPath,
		v1 + apis.SBOMCalculationCommandPath:
		return apiauth.Attributes{Group: apiGroup, Resource: apiResource, Verb: "create"}, true
	}
	// scanStatus, diagnostics and anything unknown under /v1/ need get.
	return apiauth.Attributes{Group: apiGroup, Resource: apiResource, Verb: "get"}, strings.HasPrefix(p, v1) || p == strings.TrimSuffix(v1, "/")
}

// newAPIAuth builds the gin auth middleware from the environment.
func newAPIAuth(ctx context.Context) (gin.HandlerFunc, error) {
	cfg := apiauth.Config{Route: apiAuthRoute}
	if os.Getenv(apiauth.DisabledEnv) != "true" {
		ns := os.Getenv("POD_NAMESPACE")
		if ns == "" {
			return nil, errors.New("POD_NAMESPACE must be set for API auth (or set " + apiauth.DisabledEnv + "=true)")
		}
		k8sConfig := k8sinterface.GetK8sConfig()
		if k8sConfig == nil {
			return nil, errors.New("in-cluster kube config not available for API auth")
		}
		clientset, err := kubernetes.NewForConfig(k8sConfig)
		if err != nil {
			return nil, err
		}
		cfg.Client = clientset
		cfg.Namespace = ns
		cfg.Audience = os.Getenv("KS_API_AUDIENCE")
		if cfg.Audience == "" {
			cfg.Audience = "kubescape.io"
		}
	}
	mw, err := apiauth.New(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return ginWrap(mw), nil
}

// ginWrap adapts a net/http middleware to gin; the request is aborted unless the
// middleware let it through.
func ginWrap(mw func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		reached := false
		h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			reached = true
			c.Request = r
			c.Next()
		})
		mw(h).ServeHTTP(c.Writer, c.Request)
		if !reached {
			c.Abort()
		}
	}
}
