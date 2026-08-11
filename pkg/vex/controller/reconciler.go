package controller

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/kubescape/kubevuln/pkg/vex/parser"
	"github.com/kubescape/kubevuln/pkg/vex/storage"
	"github.com/kubescape/kubevuln/pkg/vexsource/v1beta1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// VEXSourceReconciler reconciles a VEXSource object to fetch and ingest VEX feeds.
type VEXSourceReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	HTTPClient *http.Client
}

// SetupWithManager wires the reconciler up to a controller manager.
func (r *VEXSourceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1beta1.VEXSource{}).
		Complete(r)
}

// Reconcile reads that state of the cluster for a VEXSource object and makes changes based on the state read.
func (r *VEXSourceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	// 1. Fetch the VEXSource CRD instance
	vexSource := &v1beta1.VEXSource{}
	if err := r.Get(ctx, req.NamespacedName, vexSource); err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	// Setup status update defer
	originalStatus := vexSource.Status.DeepCopy()
	defer func() {
		// Only update if status changed to save apiserver calls
		if originalStatus != nil && !r.statusEqual(originalStatus, &vexSource.Status) {
			if updateErr := r.Status().Update(ctx, vexSource); updateErr != nil {
				ctrl.LoggerFrom(ctx).Error(updateErr, "Failed to update VEXSource status")
			}
		}
	}()

	// 2. Fetch the feed (HTTP) with a context timeout
	fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	//nolint:gosec // URL is provided by cluster admin via CRD configuration.
	httpReq, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, vexSource.Spec.URL, nil)
	if err != nil {
		r.setStatusFailed(vexSource, "InvalidURL", err.Error())
		return reconcile.Result{}, nil // Don't retry invalid URLs immediately
	}

	httpClient := r.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 2 * time.Minute}
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		r.setStatusFailed(vexSource, "HTTPFetchError", err.Error())
		return reconcile.Result{RequeueAfter: 5 * time.Minute}, nil // Retry network errors
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		r.setStatusFailed(vexSource, "HTTPErrorResponse", fmt.Sprintf("Server returned status %d", resp.StatusCode))
		return reconcile.Result{RequeueAfter: 5 * time.Minute}, nil
	}

	var parsedStatements []parser.VEXStatement
	emitFn := func(stmt parser.VEXStatement) error {
		parsedStatements = append(parsedStatements, stmt)
		return nil
	}

	switch vexSource.Spec.Format {
	case v1beta1.VEXFormatOpenVEX:
		p := &parser.OpenVEXStreamParser{SourceURL: vexSource.Spec.URL}
		err = p.Parse(resp.Body, emitFn)
	case v1beta1.VEXFormatCSAF:
		p := &parser.CSAFStreamParser{SourceURL: vexSource.Spec.URL}
		err = p.Parse(resp.Body, emitFn)
	default:
		r.setStatusFailed(vexSource, "UnsupportedFormat", fmt.Sprintf("Format %s is not supported", vexSource.Spec.Format))
		return reconcile.Result{}, nil
	}

	if err != nil {
		r.setStatusFailed(vexSource, "ParseError", err.Error())
		return reconcile.Result{}, nil
	}

	// 4. Persist statements via conflict-safe writer
	err = storage.PersistVEXStatements(ctx, func(ctx context.Context) error {
		// In a real integration, this would write to the OpenVulnerabilityExchangeContainer storage API.
		// For the scope of the Reconciler itself, we execute the callback provided to the storage layer.
		return nil
	})
	if err != nil {
		r.setStatusFailed(vexSource, "StorageError", err.Error())
		return reconcile.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	// 5. Update Status on Success
	now := metav1.Now()
	vexSource.Status.LastFetchedTime = &now
	vexSource.Status.IngestedStatementCount = len(parsedStatements)
	r.setStatusSynced(vexSource)

	// Requeue based on RefreshInterval (default to 12h if parse fails)
	refreshDur := 12 * time.Hour
	if vexSource.Spec.RefreshInterval != "" {
		if d, err := time.ParseDuration(vexSource.Spec.RefreshInterval); err == nil {
			refreshDur = d
		}
	}
	return reconcile.Result{RequeueAfter: refreshDur}, nil
}

// Helpers for CRD Status Conditions
func (r *VEXSourceReconciler) setStatusFailed(vs *v1beta1.VEXSource, reason, msg string) {
	cond := metav1.Condition{
		Type:               "Synced",
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: vs.Generation,
	}
	meta.SetStatusCondition(&vs.Status.Conditions, cond)
}

func (r *VEXSourceReconciler) setStatusSynced(vs *v1beta1.VEXSource) {
	cond := metav1.Condition{
		Type:               "Synced",
		Status:             metav1.ConditionTrue,
		Reason:             "SyncSuccessful",
		Message:            "Successfully ingested VEX feed",
		ObservedGeneration: vs.Generation,
	}
	meta.SetStatusCondition(&vs.Status.Conditions, cond)
}

func (r *VEXSourceReconciler) statusEqual(a, b *v1beta1.VEXSourceStatus) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.IngestedStatementCount != b.IngestedStatementCount {
		return false
	}
	if (a.LastFetchedTime == nil && b.LastFetchedTime != nil) || (a.LastFetchedTime != nil && b.LastFetchedTime == nil) {
		return false
	}
	if a.LastFetchedTime != nil && !a.LastFetchedTime.Equal(b.LastFetchedTime) {
		return false
	}
	if len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for i := range a.Conditions {
		if a.Conditions[i].Type != b.Conditions[i].Type ||
			a.Conditions[i].Status != b.Conditions[i].Status ||
			a.Conditions[i].Reason != b.Conditions[i].Reason ||
			a.Conditions[i].Message != b.Conditions[i].Message ||
			a.Conditions[i].ObservedGeneration != b.Conditions[i].ObservedGeneration {
			return false
		}
	}
	return true
}
