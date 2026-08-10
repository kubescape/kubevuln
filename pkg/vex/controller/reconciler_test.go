package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kubescape/kubevuln/pkg/vexsource/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestVEXSourceReconciler_Reconcile(t *testing.T) {
	// Setup a fake HTTP server returning valid OpenVEX JSON
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"@context": "https://openvex.dev/ns/v0.2.0",
			"@id": "https://openvex.dev/docs/public/vex-9a3b211",
			"author": "Mock Vendor",
			"timestamp": "2026-08-10T12:00:00Z",
			"version": 1,
			"statements": [
				{
					"vulnerability": {"name": "CVE-2024-1234"},
					"timestamp": "2026-08-10T12:00:00Z",
					"products": [
						"pkg:apk/alpine/curl@8.5.0-r0?arch=x86_64"
					],
					"status": "not_affected",
					"justification": "vulnerable_code_not_in_execute_path"
				}
			]
		}`))
	}))
	defer mockServer.Close()

	// Setup fake k8s client
	scheme := runtime.NewScheme()
	_ = v1beta1.AddToScheme(scheme)

	vexSource := &v1beta1.VEXSource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vex",
			Namespace: "default",
		},
		Spec: v1beta1.VEXSourceSpec{
			URL:    mockServer.URL,
			Format: v1beta1.VEXFormatOpenVEX,
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1beta1.VEXSource{}).WithObjects(vexSource).Build()

	r := &VEXSourceReconciler{
		Client:     client,
		Scheme:     scheme,
		HTTPClient: mockServer.Client(),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-vex",
			Namespace: "default",
		},
	}

	res, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RequeueAfter != 12*time.Hour {
		t.Errorf("expected 12h requeue, got %v", res.RequeueAfter)
	}

	// Verify the status was updated
	updated := &v1beta1.VEXSource{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	if err != nil {
		t.Fatalf("failed to get updated resource: %v", err)
	}

	if updated.Status.IngestedStatementCount != 1 {
		t.Errorf("expected 1 statement, got %d", updated.Status.IngestedStatementCount)
	}
	if len(updated.Status.Conditions) == 0 || updated.Status.Conditions[0].Type != "Synced" || updated.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("expected Synced=True condition, got %v", updated.Status.Conditions)
	}
}

func TestVEXSourceReconciler_HTTPError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1beta1.AddToScheme(scheme)

	vexSource := &v1beta1.VEXSource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vex",
			Namespace: "default",
		},
		Spec: v1beta1.VEXSourceSpec{
			URL:    "http://127.0.0.1:0/broken", // Will fail to connect
			Format: v1beta1.VEXFormatOpenVEX,
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1beta1.VEXSource{}).WithObjects(vexSource).Build()

	r := &VEXSourceReconciler{
		Client:     client,
		Scheme:     scheme,
		HTTPClient: http.DefaultClient,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-vex",
			Namespace: "default",
		},
	}

	res, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Network error should trigger a fast requeue (5 minutes)
	if res.RequeueAfter != 5*time.Minute {
		t.Errorf("expected 5m requeue for HTTP error, got %v", res.RequeueAfter)
	}

	updated := &v1beta1.VEXSource{}
	_ = client.Get(context.Background(), req.NamespacedName, updated)

	if len(updated.Status.Conditions) == 0 || updated.Status.Conditions[0].Status != metav1.ConditionFalse || updated.Status.Conditions[0].Reason != "HTTPFetchError" {
		t.Errorf("expected Synced=False with HTTPFetchError, got %v", updated.Status.Conditions)
	}
}
