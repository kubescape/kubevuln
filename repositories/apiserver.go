package repositories

import (
	"context"
	"crypto/sha256"
	stderrors "errors"
	"fmt"
	"maps"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akyoto/cache"
	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	sev1beta1 "github.com/kubescape/kubevuln/pkg/securityexception/v1beta1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	fakespdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1/fake"
	"github.com/openvex/go-vex/pkg/vex"
	"go.opentelemetry.io/otel"
	"golang.org/x/mod/semver"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	fakedynamic "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
	k8scache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
)

const (
	vulnerabilityManifestSummaryKindPlural string = "vulnerabilitymanifests"
	vulnSummaryContNameFormat              string = "%s-%s-%s" // "<kind>-<name>-<container-name>"

	// timestampMetadataKey is the scan time, in Unix seconds, stamped on every summary
	// manifest kubevuln writes. It lives here rather than coming from
	// k8s-interface/instanceidhandler/v1/helpers, like every other metadata key on these
	// objects, because that package has no key for it: its nearest neighbour,
	// ReportTimestampMetadataKey ("kubescape.io/report-timestamp"), is a different key
	// written by a different component. Changing the string would orphan the annotation on
	// already-stored manifests, so it stays as it is.
	timestampMetadataKey string = "kubescape.io/timestamp"
)

// securityExceptionListCacheCleaningInterval/TTL bound how stale the raw SecurityException/
// ClusterSecurityException List() results served by GetSecurityExceptions can be. Unlike
// BackendAdapter's exceptionsCacheTTL (5m, keyed per workload), this cache sits below the
// per-workload match/filter step and is keyed per namespace (SecurityException) or cluster-wide
// (ClusterSecurityException), so every workload sharing that scope reuses the same List() —
// see #510. 30s keeps the data close to live while still collapsing a burst of many
// workloads/images scanned back-to-back into a single List() call.
const (
	securityExceptionListCacheCleaningInterval = 30 * time.Second
	securityExceptionListCacheTTL              = 30 * time.Second
	clusterSecurityExceptionListCacheKey       = "cse"
	securityExceptionListCacheKeyPrefix        = "se/"
)

// APIServerStore implements both CVERepository and SBOMRepository with in-cluster storage (apiserver) to be used for production
type APIServerStore struct {
	StorageClient spdxv1beta1.SpdxV1beta1Interface
	DynamicClient dynamic.Interface
	Namespace     string

	// securityExceptionListCache caches the raw List() results GetSecurityExceptions reads;
	// nil is safe (falls back to always listing, e.g. in tests that construct APIServerStore
	// literals directly instead of through the constructors below).
	securityExceptionListCache *cache.Cache

	// securityExceptionCacheEntries backs the compare-and-swap that keeps a List() in flight
	// when a CRD change invalidates its cache key from silently re-populating the cache with
	// its now-stale result afterward — see securityExceptionCacheEntry's doc comment and #733.
	// Zero value (empty sync.Map) is ready to use, so this needs no constructor initialization.
	securityExceptionCacheEntries sync.Map // cacheKey (string) -> *securityExceptionCacheEntry

	securityExceptionInformerStop context.CancelFunc
}

// securityExceptionCacheEntry pairs a cache key's invalidation generation with the mutex that
// makes reading/bumping it, and conditionally writing securityExceptionListCache for that key,
// atomic with respect to each other. See securityExceptionCacheEntry (the method) for why this
// exists: a plain generation counter alone still leaves a check-then-act gap between reading it
// and calling Set().
type securityExceptionCacheEntry struct {
	mu         sync.Mutex
	generation uint64
}

// securityExceptionCacheEntry returns the entry for cacheKey, creating it on first use. Entries
// are never removed, so the key count grows with every distinct namespace that has ever had
// SecurityExceptions listed, plus one for the cluster-scoped key. Each entry is small, so this
// is slow growth rather than an urgent leak, but it is not bounded in clusters where namespaces
// are created and deleted continuously.
func (a *APIServerStore) securityExceptionCacheEntry(cacheKey string) *securityExceptionCacheEntry {
	v, _ := a.securityExceptionCacheEntries.LoadOrStore(cacheKey, &securityExceptionCacheEntry{})
	return v.(*securityExceptionCacheEntry)
}

// invalidateSecurityExceptionCacheKey evicts cacheKey from securityExceptionListCache and bumps
// its generation, atomically with respect to beginSecurityExceptionCacheRefresh/
// trySetSecurityExceptionCache below: whichever of an invalidation and a racing List()'s
// conditional Set() acquires the entry's mutex last determines the outcome, and in either order
// the result is correct (see trySetSecurityExceptionCache's doc comment for why).
func (a *APIServerStore) invalidateSecurityExceptionCacheKey(cacheKey string) {
	entry := a.securityExceptionCacheEntry(cacheKey)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	entry.generation++
	a.securityExceptionListCache.Delete(cacheKey)
}

// beginSecurityExceptionCacheRefresh snapshots cacheKey's current generation before a caller
// starts a List() call for it, to later pass to trySetSecurityExceptionCache.
func (a *APIServerStore) beginSecurityExceptionCacheRefresh(cacheKey string) (seenGeneration uint64) {
	entry := a.securityExceptionCacheEntry(cacheKey)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.generation
}

// trySetSecurityExceptionCache writes value to securityExceptionListCache under cacheKey only if
// cacheKey's generation is still seenGeneration, i.e. no invalidation has happened for it since
// the caller's beginSecurityExceptionCacheRefresh snapshot. This closes the race #733 describes:
// without it, a List() started before a CRD change could still write its now-stale result to the
// cache after the informer's invalidation for that change already ran, silently undoing it. The
// check and the write happen under the same per-key mutex invalidateSecurityExceptionCacheKey
// uses, so there is no gap between "check the generation" and "write the cache" for a concurrent
// invalidation to land in — unlike a bare atomic counter compared just before an unguarded Set().
// The List() call itself is deliberately not covered by this lock: holding it across a network
// call would let a slow List() delay an unrelated invalidation for the same key, and informers
// typically deliver events to a handler serially, so that delay could stall processing of other,
// unrelated CRD events too.
func (a *APIServerStore) trySetSecurityExceptionCache(cacheKey string, seenGeneration uint64, value interface{}) {
	entry := a.securityExceptionCacheEntry(cacheKey)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.generation != seenGeneration {
		return
	}
	a.securityExceptionListCache.Set(cacheKey, value, securityExceptionListCacheTTL)
}

var (
	securityExceptionGVR = schema.GroupVersionResource{
		Group:    "kubescape.io",
		Version:  "v1beta1",
		Resource: "securityexceptions",
	}
	clusterSecurityExceptionGVR = schema.GroupVersionResource{
		Group:    "kubescape.io",
		Version:  "v1beta1",
		Resource: "clustersecurityexceptions",
	}
	namespaceGVR = schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	}
)

var _ ports.ContainerProfileRepository = (*APIServerStore)(nil)

var _ ports.CVERepository = (*APIServerStore)(nil)

var _ ports.SBOMRepository = (*APIServerStore)(nil)

var _ ports.SecurityExceptionRepository = (*APIServerStore)(nil)

// NewAPIServerStorage initializes the APIServerStore struct
func NewAPIServerStorage(namespace string) (*APIServerStore, error) {

	config := k8sinterface.GetK8sConfig()
	if config == nil {
		return nil, fmt.Errorf("failed to get k8s config")
	}
	// Typed client for storage API (uses protobuf)
	protoConfig := *config
	protoConfig.AcceptContentTypes = "application/vnd.kubernetes.protobuf"
	protoConfig.ContentType = "application/vnd.kubernetes.protobuf"
	clientset, err := versioned.NewForConfig(&protoConfig)
	if err != nil {
		return nil, err
	}
	// Dynamic client for CRDs (uses JSON, separate rate limiter)
	dynConfig := *config
	dynConfig.QPS = 50
	dynConfig.Burst = 100
	dynClient, err := dynamic.NewForConfig(&dynConfig)
	if err != nil {
		return nil, err
	}
	store := &APIServerStore{
		StorageClient:              clientset.SpdxV1beta1(),
		DynamicClient:              dynClient,
		Namespace:                  namespace,
		securityExceptionListCache: cache.New(securityExceptionListCacheCleaningInterval),
	}
	store.enableSecurityExceptionCacheInvalidation(context.Background())
	return store, nil
}

type fakeStorageClientset struct {
	k8stesting.Fake
	tracker k8stesting.ObjectTracker
}

func (c *fakeStorageClientset) SpdxV1beta1() spdxv1beta1.SpdxV1beta1Interface {
	return &fakespdxv1beta1.FakeSpdxV1beta1{Fake: &c.Fake}
}

func (c *fakeStorageClientset) Tracker() k8stesting.ObjectTracker {
	return c.tracker
}

func newFakeStorageClientset(objects ...runtime.Object) *fakeStorageClientset {
	scheme := runtime.NewScheme()
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
	if err := v1beta1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	codecs := serializer.NewCodecFactory(scheme)
	tracker := k8stesting.NewFieldManagedObjectTracker(
		scheme,
		codecs.UniversalDecoder(),
		managedfields.NewDeducedTypeConverter(),
	)
	for _, obj := range objects {
		if err := tracker.Add(obj); err != nil {
			panic(err)
		}
	}

	clientset := &fakeStorageClientset{tracker: tracker}
	clientset.AddReactor("*", "*", k8stesting.ObjectReaction(tracker))
	clientset.AddWatchReactor("*", func(action k8stesting.Action) (bool, watch.Interface, error) {
		var opts metav1.ListOptions
		if watchAction, ok := action.(k8stesting.WatchActionImpl); ok {
			opts = watchAction.ListOptions
		}
		w, err := tracker.Watch(action.GetResource(), action.GetNamespace(), opts)
		if err != nil {
			return false, nil, err
		}
		return true, w, nil
	})

	return clientset
}

func newFakeAPIServerStore(namespace string, storageClient spdxv1beta1.SpdxV1beta1Interface) *APIServerStore {
	return &APIServerStore{
		StorageClient: storageClient,
		// The fake dynamic client requires every GVR it will List() to have a registered
		// list kind up front (fakedynamic.NewSimpleDynamicClient's default of an empty
		// scheme panics on List() otherwise) - register the two GVRs GetSecurityExceptions
		// uses so callers can exercise it against this fake store.
		DynamicClient: fakedynamic.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
			securityExceptionGVR:        "SecurityExceptionList",
			clusterSecurityExceptionGVR: "ClusterSecurityExceptionList",
		}),
		Namespace:                  namespace,
		securityExceptionListCache: cache.New(securityExceptionListCacheCleaningInterval),
	}
}

func NewFakeAPIServerStorage(namespace string, objects ...runtime.Object) *APIServerStore {
	return newFakeAPIServerStore(namespace, newFakeStorageClientset(objects...).SpdxV1beta1())
}

func (a *APIServerStore) enableSecurityExceptionCacheInvalidation(ctx context.Context) {
	if a == nil || a.DynamicClient == nil || a.securityExceptionListCache == nil || a.securityExceptionInformerStop != nil {
		return
	}

	watchCtx, cancel := context.WithCancel(ctx)
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(a.DynamicClient, 0, metav1.NamespaceAll, nil)

	if _, err := factory.ForResource(securityExceptionGVR).Informer().AddEventHandler(k8scache.ResourceEventHandlerFuncs{
		AddFunc:    a.invalidateSecurityExceptionCacheForObject,
		UpdateFunc: func(_, newObj interface{}) { a.invalidateSecurityExceptionCacheForObject(newObj) },
		DeleteFunc: a.invalidateSecurityExceptionCacheForObject,
	}); err != nil {
		cancel()
		logger.L().Warning("failed to register SecurityException cache invalidation handler", helpers.Error(err))
		return
	}

	if _, err := factory.ForResource(clusterSecurityExceptionGVR).Informer().AddEventHandler(k8scache.ResourceEventHandlerFuncs{
		AddFunc:    func(interface{}) { a.invalidateClusterSecurityExceptionCache() },
		UpdateFunc: func(interface{}, interface{}) { a.invalidateClusterSecurityExceptionCache() },
		DeleteFunc: func(interface{}) { a.invalidateClusterSecurityExceptionCache() },
	}); err != nil {
		cancel()
		logger.L().Warning("failed to register ClusterSecurityException cache invalidation handler", helpers.Error(err))
		return
	}

	a.securityExceptionInformerStop = cancel
	go factory.Start(watchCtx.Done())
}

func (a *APIServerStore) invalidateSecurityExceptionCacheForObject(obj interface{}) {
	if a == nil || a.securityExceptionListCache == nil {
		return
	}

	u := unstructuredFromEvent(obj)
	if u == nil {
		a.invalidateAllSecurityExceptionCaches()
		return
	}
	if namespace := u.GetNamespace(); namespace != "" {
		a.invalidateSecurityExceptionCacheKey(securityExceptionListCacheKeyPrefix + namespace)
		return
	}
	a.invalidateAllSecurityExceptionCaches()
}

func (a *APIServerStore) invalidateClusterSecurityExceptionCache() {
	if a == nil || a.securityExceptionListCache == nil {
		return
	}
	a.invalidateSecurityExceptionCacheKey(clusterSecurityExceptionListCacheKey)
}

// invalidateAllSecurityExceptionCaches invalidates every namespaced SecurityException cache key
// this process has ever seen, for events unstructuredFromEvent could not resolve to a specific
// namespace (a defensive fallback, not the normal add/update/delete path). It ranges over
// securityExceptionCacheEntries rather than securityExceptionListCache so it also covers a key
// with a List() currently in flight but no cached value yet (see beginSecurityExceptionCacheRefresh):
// that entry already exists by the time its List() call started, even though it may not exist in
// securityExceptionListCache until that List() returns.
func (a *APIServerStore) invalidateAllSecurityExceptionCaches() {
	if a == nil || a.securityExceptionListCache == nil {
		return
	}
	a.securityExceptionCacheEntries.Range(func(key, _ interface{}) bool {
		if cacheKey, ok := key.(string); ok && strings.HasPrefix(cacheKey, securityExceptionListCacheKeyPrefix) {
			a.invalidateSecurityExceptionCacheKey(cacheKey)
		}
		return true
	})
}

func unstructuredFromEvent(obj interface{}) *unstructured.Unstructured {
	switch typed := obj.(type) {
	case *unstructured.Unstructured:
		return typed
	case k8scache.DeletedFinalStateUnknown:
		if u, ok := typed.Obj.(*unstructured.Unstructured); ok {
			return u
		}
	case *k8scache.DeletedFinalStateUnknown:
		if u, ok := typed.Obj.(*unstructured.Unstructured); ok {
			return u
		}
	}
	return nil
}

// GetSecurityExceptions lists both namespaced SecurityExceptions and cluster-scoped
// ClusterSecurityExceptions. A List() failure is returned as an error rather than only
// logged: the caller (BackendAdapter.GetCVEExceptions) relies on a non-nil error here to
// avoid caching a degraded, incomplete exception set for exceptionsCacheTTL — see #477.
//
// A conversion failure on an individual item is reported the same way, while the items that
// did convert are still returned. It used to be only logged and skipped, on the grounds that
// a malformed single object is not a listing-wide failure. That holds for whether to abandon
// the list, and this does not abandon it: the caller still receives and applies everything
// that converted. What it cannot do is call the set complete, because the flag derived from
// this error is what decides whether a suppression that is now missing counts as a deletion
// (see reconcileCachedCVE) — and a skipped exception is missing for exactly the same reason
// a failed List() leaves the set short.
//
// Both lists are served from securityExceptionListCache when available and fresh: the raw
// List() results are the same for every workload in a given namespace (SecurityException) or
// in the whole cluster (ClusterSecurityException), but without this cache each distinct
// workload/image scanned re-triggers its own List() call — see #510. A List() failure is
// never cached, so a transient apiserver hiccup self-heals on the next call instead of being
// pinned for the TTL.
func (a *APIServerStore) GetSecurityExceptions(ctx context.Context, namespace string) ([]sev1beta1.SecurityException, []sev1beta1.ClusterSecurityException, error) {
	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var listErrs []error

	// Only list namespaced exceptions when namespace is provided
	var exceptions []sev1beta1.SecurityException
	if namespace != "" {
		var err error
		exceptions, err = a.listSecurityExceptions(ctx, listCtx, namespace)
		if err != nil {
			listErrs = append(listErrs, err)
		}
	}

	clusterExceptions, err := a.listClusterSecurityExceptions(ctx, listCtx)
	if err != nil {
		listErrs = append(listErrs, err)
	}

	return exceptions, clusterExceptions, stderrors.Join(listErrs...)
}

// listSecurityExceptions returns the namespaced SecurityExceptions for namespace, from
// securityExceptionListCache when a fresh entry exists. The write back to the cache after a
// List() is conditional on no invalidation having raced it (see trySetSecurityExceptionCache) -
// without that, a List() started just before a SecurityException change in namespace would
// silently re-populate the cache with the pre-change result after the informer had already
// evicted it — see #733.
func (a *APIServerStore) listSecurityExceptions(ctx, listCtx context.Context, namespace string) ([]sev1beta1.SecurityException, error) {
	cacheKey := securityExceptionListCacheKeyPrefix + namespace
	var seenGeneration uint64
	if a.securityExceptionListCache != nil {
		if cached, ok := a.securityExceptionListCache.Get(cacheKey); ok {
			return cached.([]sev1beta1.SecurityException), nil
		}
		seenGeneration = a.beginSecurityExceptionCacheRefresh(cacheKey)
	}

	seList, err := a.DynamicClient.Resource(securityExceptionGVR).Namespace(namespace).List(listCtx, metav1.ListOptions{})
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to list SecurityExceptions", helpers.Error(err), helpers.String("namespace", namespace))
		return nil, fmt.Errorf("failed to list SecurityExceptions: %w", err)
	}

	var exceptions []sev1beta1.SecurityException
	var convErrs []error
	for i := range seList.Items {
		var se sev1beta1.SecurityException
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(seList.Items[i].Object, &se); err != nil {
			logger.L().Ctx(ctx).Warning("failed to convert SecurityException", helpers.Error(err),
				helpers.String("namespace", namespace), helpers.String("name", seList.Items[i].GetName()))
			convErrs = append(convErrs, fmt.Errorf("converting SecurityException %s/%s: %w", namespace, seList.Items[i].GetName(), err))
			continue
		}
		exceptions = append(exceptions, se)
	}

	// A dropped exception leaves the set incomplete just as a failed List() does, so it is
	// reported the same way and not cached. Returning it as complete would let the caller
	// persist the missing suppressions as removals and republish VEX from a set that is
	// quietly short an entry; caching it would pin that for the TTL rather than letting the
	// next call self-heal.
	if len(convErrs) > 0 {
		return exceptions, stderrors.Join(convErrs...)
	}

	if a.securityExceptionListCache != nil {
		a.trySetSecurityExceptionCache(cacheKey, seenGeneration, exceptions)
	}
	return exceptions, nil
}

// listClusterSecurityExceptions returns every ClusterSecurityException in the cluster, from
// securityExceptionListCache when a fresh entry exists. The result is the same regardless of
// which workload/namespace triggered the call, so it is cached under a single cluster-wide key.
// The write back to the cache after a List() is conditional on no invalidation having raced it -
// see listSecurityExceptions' and trySetSecurityExceptionCache's doc comments, and #733.
func (a *APIServerStore) listClusterSecurityExceptions(ctx, listCtx context.Context) ([]sev1beta1.ClusterSecurityException, error) {
	var seenGeneration uint64
	if a.securityExceptionListCache != nil {
		if cached, ok := a.securityExceptionListCache.Get(clusterSecurityExceptionListCacheKey); ok {
			return cached.([]sev1beta1.ClusterSecurityException), nil
		}
		seenGeneration = a.beginSecurityExceptionCacheRefresh(clusterSecurityExceptionListCacheKey)
	}

	cseList, err := a.DynamicClient.Resource(clusterSecurityExceptionGVR).List(listCtx, metav1.ListOptions{})
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to list ClusterSecurityExceptions", helpers.Error(err))
		return nil, fmt.Errorf("failed to list ClusterSecurityExceptions: %w", err)
	}

	var clusterExceptions []sev1beta1.ClusterSecurityException
	var convErrs []error
	for i := range cseList.Items {
		var cse sev1beta1.ClusterSecurityException
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(cseList.Items[i].Object, &cse); err != nil {
			logger.L().Ctx(ctx).Warning("failed to convert ClusterSecurityException", helpers.Error(err),
				helpers.String("name", cseList.Items[i].GetName()))
			convErrs = append(convErrs, fmt.Errorf("converting ClusterSecurityException %s: %w", cseList.Items[i].GetName(), err))
			continue
		}
		clusterExceptions = append(clusterExceptions, cse)
	}

	// See listSecurityExceptions: a dropped exception is an incomplete set, reported and
	// left uncached the same way a failed List() is.
	if len(convErrs) > 0 {
		return clusterExceptions, stderrors.Join(convErrs...)
	}

	if a.securityExceptionListCache != nil {
		a.trySetSecurityExceptionCache(clusterSecurityExceptionListCacheKey, seenGeneration, clusterExceptions)
	}
	return clusterExceptions, nil
}

// GetWorkloadLabels resolves the labels of a workload so that a
// SecurityException's match.objectSelector can be evaluated. The workload's
// GroupVersionResource is derived from its kind; if it cannot be resolved or the
// workload is not found, nil labels are returned (the selector then matches
// nothing, i.e. the exception is not applied — the safe default for a
// suppression feature).
func (a *APIServerStore) GetWorkloadLabels(ctx context.Context, namespace, kind, name string) (map[string]string, error) {
	if namespace == "" || kind == "" || name == "" {
		return nil, nil
	}
	gvr, err := k8sinterface.GetGroupVersionResource(kind)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve GroupVersionResource for kind %q: %w", kind, err)
	}
	getCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	obj, err := a.DynamicClient.Resource(gvr).Namespace(namespace).Get(getCtx, name, metav1.GetOptions{})
	if err != nil {
		// Propagate NotFound as an error (rather than nil labels) so the caller
		// fails closed: a negative objectSelector must not match a workload that
		// could not be resolved.
		return nil, err
	}
	return obj.GetLabels(), nil
}

// GetNamespaceLabels resolves the labels of a namespace so that a
// ClusterSecurityException's match.namespaceSelector can be evaluated.
func (a *APIServerStore) GetNamespaceLabels(ctx context.Context, name string) (map[string]string, error) {
	if name == "" {
		return nil, nil
	}
	getCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	obj, err := a.DynamicClient.Resource(namespaceGVR).Get(getCtx, name, metav1.GetOptions{})
	if err != nil {
		// Propagate NotFound as an error so the caller fails closed (see
		// GetWorkloadLabels).
		return nil, err
	}
	return obj.GetLabels(), nil
}

func (a *APIServerStore) GetContainerProfile(ctx context.Context, namespace string, name string) (v1beta1.ContainerProfile, error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetContainerProfile")
	defer span.End()
	if name == "" {
		logger.L().Debug("empty name provided, skipping container profile retrieval")
		return v1beta1.ContainerProfile{}, nil
	}
	profile, err := a.StorageClient.ContainerProfiles(namespace).Get(ctx, name, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		logger.L().Debug("container profile not found in storage",
			helpers.String("name", name))
		return v1beta1.ContainerProfile{}, nil
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to get container profile from apiserver", helpers.Error(err),
			helpers.String("name", name))
		return v1beta1.ContainerProfile{}, fmt.Errorf("failed to get container profile from apiserver: %w", err)
	}
	return *profile, nil
}

func (a *APIServerStore) GetCVE(ctx context.Context, name, SBOMCreatorVersion, CVEScannerVersion, CVEDBVersion string) (domain.CVEManifest, error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetCVE")
	defer span.End()
	if name == "" {
		logger.L().Debug("empty name provided, skipping CVE retrieval")
		return domain.CVEManifest{}, nil
	}
	manifest, err := a.StorageClient.VulnerabilityManifests(a.Namespace).Get(ctx, name, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		logger.L().Debug("CVE manifest not found in storage",
			helpers.String("name", name))
		return domain.CVEManifest{}, nil
	case err != nil:
		return domain.CVEManifest{}, fmt.Errorf("failed to get CVE manifest from apiserver: %w", err)
	}
	// discard the manifest if it was created by an older version of the scanner
	if manifest.Annotations[helpersv1.ToolVersionMetadataKey] != SBOMCreatorVersion ||
		manifest.Spec.Metadata.Tool.Version != CVEScannerVersion ||
		manifest.Spec.Metadata.Tool.DatabaseVersion != CVEDBVersion {
		logger.L().Debug("discarding CVE manifest with outdated scanner version",
			helpers.String("name", name),
			helpers.String("annotations sbom creator version", manifest.Annotations[helpersv1.ToolVersionMetadataKey]),
			helpers.String("manifest scanner version", manifest.Spec.Metadata.Tool.Version),
			helpers.String("manifest DB version", manifest.Spec.Metadata.Tool.DatabaseVersion),
			helpers.String("wanted sbom creator version", SBOMCreatorVersion),
			helpers.String("wanted scanner version", CVEScannerVersion),
			helpers.String("wanted DB version", CVEDBVersion))
		return domain.CVEManifest{}, nil
	}
	logger.L().Debug("got CVE manifest from storage",
		helpers.String("name", name))
	return domain.CVEManifest{
		Name:               name,
		Annotations:        manifest.Annotations,
		Labels:             manifest.Labels,
		SBOMCreatorVersion: SBOMCreatorVersion,
		CVEScannerVersion:  CVEScannerVersion,
		CVEDBVersion:       CVEDBVersion,
		Content:            &manifest.Spec.Payload,
	}, nil
}
func (a *APIServerStore) GetCVESummary(ctx context.Context) (*v1beta1.VulnerabilityManifestSummary, error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetCVESummary")
	defer span.End()
	name, err := GetCVESummaryK8sResourceName(ctx)
	if err != nil {
		return nil, err
	}
	if name == "" {
		logger.L().Debug("empty name provided, skipping summary CVE retrieval")
		return nil, nil
	}
	workloadNamespace, err := GetCVESummaryK8sResourceNamespace(ctx)
	if err != nil {
		return nil, err
	}
	if workloadNamespace == "" {
		workloadNamespace = a.Namespace
	}
	manifest, err := a.StorageClient.VulnerabilityManifestSummaries(workloadNamespace).Get(ctx, name, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		logger.L().Debug("summary CVE manifest not found in storage",
			helpers.String("name", name),
			helpers.String("namespace", workloadNamespace))
		return nil, nil
	case err != nil:
		logger.L().Ctx(ctx).Warning("failed to get summary CVE manifest from apiserver", helpers.Error(err),
			helpers.String("name", name),
			helpers.String("namespace", workloadNamespace))
		return nil, err
	}

	logger.L().Debug("got summary CVE manifest from storage",
		helpers.String("name", name),
		helpers.String("namespace", workloadNamespace))
	return manifest, nil
}

func (a *APIServerStore) StoreCVE(ctx context.Context, cve domain.CVEManifest, withRelevancy bool) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreCVEWithFullContent")
	defer span.End()

	if cve.Name == "" {
		logger.L().Debug("skipping storing CVE manifest with empty name",
			helpers.String("relevant", strconv.FormatBool(withRelevancy)))
		return nil
	}
	if cve.Labels == nil {
		cve.Labels = make(map[string]string)
	}

	if withRelevancy {
		cve.Labels[helpersv1.ContextMetadataKey] = helpersv1.ContextMetadataKeyFiltered
	} else {
		cve.Labels[helpersv1.ContextMetadataKey] = helpersv1.ContextMetadataKeyNonFiltered
	}

	manifest := v1beta1.VulnerabilityManifest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        cve.Name,
			Annotations: cve.Annotations,
			Labels:      cve.Labels,
		},
		Spec: v1beta1.VulnerabilityManifestSpec{
			Metadata: v1beta1.VulnerabilityManifestMeta{
				WithRelevancy: withRelevancy,
				Tool: v1beta1.VulnerabilityManifestToolMeta{
					Name:            cve.CVEScannerName,
					Version:         cve.CVEScannerVersion,
					DatabaseVersion: cve.CVEDBVersion,
				},
			},
		},
	}
	if cve.Content != nil {
		manifest.Spec.Payload = *cve.Content
	}
	return createOrUpdate(ctx, a.StorageClient.VulnerabilityManifests(a.Namespace),
		"CVE manifest", cve.Name, &manifest,
		func(existing *v1beta1.VulnerabilityManifest) {
			existing.Annotations = mergeMaps(existing.Annotations, manifest.Annotations)
			existing.Labels = mergeMaps(existing.Labels, manifest.Labels)
			existing.Spec = manifest.Spec
		},
		helpers.String("relevant", strconv.FormatBool(withRelevancy)))
}

func parseVulnerabilitiesComponents(cve domain.CVEManifest, cvep domain.CVEManifest, namespace string, withRelevancy bool) v1beta1.VulnerabilitiesComponents {
	vulComp := v1beta1.VulnerabilitiesComponents{}

	if withRelevancy {
		vulComp.WorkloadVulnerabilitiesObj.Name = cvep.Name
		vulComp.WorkloadVulnerabilitiesObj.Kind = vulnerabilityManifestSummaryKindPlural
		vulComp.WorkloadVulnerabilitiesObj.Namespace = namespace
	}
	vulComp.ImageVulnerabilitiesObj.Name = cve.Name
	vulComp.ImageVulnerabilitiesObj.Kind = vulnerabilityManifestSummaryKindPlural
	vulComp.ImageVulnerabilitiesObj.Namespace = namespace

	return vulComp
}

func parseSeverities(cve domain.CVEManifest, cvep domain.CVEManifest, withRelevancy bool) v1beta1.SeveritySummary {
	var critical int64
	var criticalRelevant int64
	var high int64
	var highRelevant int64
	var medium int64
	var mediumRelevant int64
	var low int64
	var lowRelevant int64
	var negligible int64
	var negligibleRelevant int64
	var unknown int64
	var unknownRelevant int64

	if cve.Content != nil {
		for i := range cve.Content.Matches {
			switch cve.Content.Matches[i].Vulnerability.Severity {
			case domain.CriticalSeverity:
				critical += 1
			case domain.HighSeverity:
				high += 1
			case domain.MediumSeverity:
				medium += 1
			case domain.LowSeverity:
				low += 1
			case domain.NegligibleSeverity:
				negligible += 1
			case domain.UnknownSeverity:
				unknown += 1
			}
		}
	}
	if withRelevancy && cvep.Content != nil {
		for i := range cvep.Content.Matches {
			switch cvep.Content.Matches[i].Vulnerability.Severity {
			case domain.CriticalSeverity:
				criticalRelevant += 1
			case domain.HighSeverity:
				highRelevant += 1
			case domain.MediumSeverity:
				mediumRelevant += 1
			case domain.LowSeverity:
				lowRelevant += 1
			case domain.NegligibleSeverity:
				negligibleRelevant += 1
			case domain.UnknownSeverity:
				unknownRelevant += 1
			}
		}
	}

	return v1beta1.SeveritySummary{
		Critical:   v1beta1.VulnerabilityCounters{All: critical, Relevant: criticalRelevant},
		High:       v1beta1.VulnerabilityCounters{All: high, Relevant: highRelevant},
		Medium:     v1beta1.VulnerabilityCounters{All: medium, Relevant: mediumRelevant},
		Low:        v1beta1.VulnerabilityCounters{All: low, Relevant: lowRelevant},
		Negligible: v1beta1.VulnerabilityCounters{All: negligible, Relevant: negligibleRelevant},
		Unknown:    v1beta1.VulnerabilityCounters{All: unknown, Relevant: unknownRelevant},
	}
}

func enrichSummaryManifestObjectAnnotations(ctx context.Context, annotations map[string]string) (map[string]string, error) {
	// Copied, not aliased: the caller passes its own manifest's map, and the entries added
	// below belong to the summary object being built rather than to that manifest. Writing
	// through left a CVE manifest carrying summary annotations it never had, which is the
	// same hazard applyExceptionsToManifest already clones to avoid.
	enrichedAnnotations := make(map[string]string, len(annotations)+3)
	maps.Copy(enrichedAnnotations, annotations)

	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return nil, domain.ErrCastingWorkload
	}
	timestamp, ok := ctx.Value(domain.TimestampKey{}).(int64)
	if !ok {
		return nil, domain.ErrMissingTimestamp
	}
	enrichedAnnotations[timestampMetadataKey] = strconv.FormatInt(timestamp, 10)
	enrichedAnnotations[helpersv1.WlidMetadataKey] = workload.Wlid
	enrichedAnnotations[helpersv1.ContainerNameMetadataKey] = workload.ContainerName

	return enrichedAnnotations, nil
}

func enrichSummaryManifestObjectLabels(ctx context.Context, labels map[string]string, withRelevancy bool) (map[string]string, error) {
	// Copied for the same reason as the annotations above.
	enrichedLabels := make(map[string]string, len(labels)+7)
	maps.Copy(enrichedLabels, labels)
	if withRelevancy {
		enrichedLabels[helpersv1.ContextMetadataKey] = helpersv1.ContextMetadataKeyFiltered
	} else {
		enrichedLabels[helpersv1.ContextMetadataKey] = helpersv1.ContextMetadataKeyNonFiltered
	}

	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return nil, domain.ErrCastingWorkload
	}

	workloadKind := wlid.GetKindFromWlid(workload.Wlid)
	if workloadKind != "" {
		groupVersionScheme, err := k8sinterface.GetGroupVersionResource(workloadKind)
		if err != nil {
			return nil, err
		}

		enrichedLabels[helpersv1.ApiGroupMetadataKey] = groupVersionScheme.Group
		enrichedLabels[helpersv1.ApiVersionMetadataKey] = groupVersionScheme.Version
		enrichedLabels[helpersv1.RelatedKindMetadataKey] = strings.ToLower(workloadKind)
		enrichedLabels[helpersv1.RelatedNameMetadataKey] = wlid.GetNameFromWlid(workload.Wlid)
		enrichedLabels[helpersv1.RelatedNamespaceMetadataKey] = wlid.GetNamespaceFromWlid(workload.Wlid)
	}
	if workload.ContainerName != "" {
		enrichedLabels[helpersv1.ContainerNameMetadataKey] = workload.ContainerName
	}

	return enrichedLabels, nil
}

func GetCVESummaryK8sResourceName(ctx context.Context) (string, error) {
	return GetCVESummaryK8sResourceNameWithCVEName(ctx, "")
}

func GetCVESummaryK8sResourceNameWithCVEName(ctx context.Context, cveName string) (string, error) {
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return "", domain.ErrCastingWorkload
	}
	kind := strings.ToLower(wlid.GetKindFromWlid(workload.Wlid))
	name := strings.ToLower(wlid.GetNameFromWlid(workload.Wlid))
	contName := strings.ToLower(workload.ContainerName)

	if kind == "" && name == "" {
		if cveName != "" {
			return cveName, nil
		}
		if workload.ImageSlug != "" {
			return workload.ImageSlug, nil
		}
		if contName != "" {
			return contName, nil
		}
	}

	return fmt.Sprintf(vulnSummaryContNameFormat, kind, name, contName), nil
}

func GetCVESummaryK8sResourceNamespace(ctx context.Context) (string, error) {
	workload, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok {
		return "", domain.ErrCastingWorkload
	}

	return wlid.GetNamespaceFromWlid(workload.Wlid), nil
}

func (a *APIServerStore) StoreCVESummary(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest, withRelevancy bool) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreCVESummary")
	defer span.End()

	if cve.Name == "" {
		logger.L().Debug("skipping storing CVE manifest with empty name",
			helpers.String("relevant", strconv.FormatBool(withRelevancy)))
		return nil
	}

	annotations, err := enrichSummaryManifestObjectAnnotations(ctx, cve.Annotations)
	if err != nil {
		return err
	}
	labels, err := enrichSummaryManifestObjectLabels(ctx, cve.Labels, withRelevancy)
	if err != nil {
		return err
	}
	summaryK8sResourceName, err := GetCVESummaryK8sResourceNameWithCVEName(ctx, cve.Name)
	if err != nil {
		return err
	}
	workloadNamespace, err := GetCVESummaryK8sResourceNamespace(ctx)
	if err != nil {
		return err
	}
	if workloadNamespace == "" {
		// fallback to default namespace
		workloadNamespace = a.Namespace
	}

	manifest := v1beta1.VulnerabilityManifestSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name:        summaryK8sResourceName,
			Annotations: annotations,
			Labels:      labels,
		},
		Spec: v1beta1.VulnerabilityManifestSummarySpec{
			Severities:      parseSeverities(cve, cvep, withRelevancy),
			Vulnerabilities: parseVulnerabilitiesComponents(cve, cvep, workloadNamespace, withRelevancy),
		},
	}
	return createOrUpdate(ctx, a.StorageClient.VulnerabilityManifestSummaries(workloadNamespace),
		"CVE summary manifest", manifest.Name, &manifest,
		func(existing *v1beta1.VulnerabilityManifestSummary) {
			existing.Annotations = mergeMaps(existing.Annotations, manifest.Annotations)
			existing.Labels = mergeMaps(existing.Labels, manifest.Labels)
			existing.Spec = manifest.Spec
		},
		helpers.String("relevant", strconv.FormatBool(withRelevancy)))
}

// summaryHasVulnerabilityData reports whether a summary already holds real scan results
func summaryHasVulnerabilityData(s *v1beta1.VulnerabilityManifestSummary) bool {
	sev := s.Spec.Severities
	if sev.Critical.All > 0 || sev.High.All > 0 || sev.Medium.All > 0 ||
		sev.Low.All > 0 || sev.Negligible.All > 0 || sev.Unknown.All > 0 {
		return true
	}
	// a real summary records the workload/image scope even with zero findings
	return s.Spec.Vulnerabilities.ImageVulnerabilitiesObj.Name != "" ||
		s.Spec.Vulnerabilities.WorkloadVulnerabilitiesObj.Name != ""
}

func (a *APIServerStore) StoreCVESummaryStub(ctx context.Context, status string) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreCVESummaryStub")
	defer span.End()

	annotations, err := enrichSummaryManifestObjectAnnotations(ctx, nil)
	if err != nil {
		return err
	}
	annotations[helpersv1.StatusMetadataKey] = status
	labels, err := enrichSummaryManifestObjectLabels(ctx, nil, false)
	if err != nil {
		return err
	}
	summaryK8sResourceName, err := GetCVESummaryK8sResourceName(ctx)
	if err != nil {
		return err
	}
	workloadNamespace, err := GetCVESummaryK8sResourceNamespace(ctx)
	if err != nil {
		return err
	}
	if workloadNamespace == "" {
		// fallback to default namespace
		workloadNamespace = a.Namespace
	}

	manifest := v1beta1.VulnerabilityManifestSummary{
		ObjectMeta: metav1.ObjectMeta{
			Name:        summaryK8sResourceName,
			Annotations: annotations,
			Labels:      labels,
		},
	}
	_, err = a.StorageClient.VulnerabilityManifestSummaries(workloadNamespace).Create(ctx, &manifest, metav1.CreateOptions{})
	switch {
	case errors.IsAlreadyExists(err):
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			// retrieve the latest version before attempting update
			result, getErr := a.StorageClient.VulnerabilityManifestSummaries(workloadNamespace).Get(ctx, manifest.Name, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			// don't overwrite a real summary with a stub status
			if summaryHasVulnerabilityData(result) {
				return nil
			}
			// refresh annotations/labels only, keep any existing Spec
			result.Annotations = mergeMaps(result.Annotations, manifest.Annotations)
			result.Labels = mergeMaps(result.Labels, manifest.Labels)
			_, updateErr := a.StorageClient.VulnerabilityManifestSummaries(workloadNamespace).Update(ctx, result, metav1.UpdateOptions{})
			return updateErr
		})
		if retryErr != nil {
			logger.L().Debug("failed to update CVE summary stub in storage", helpers.Error(retryErr),
				helpers.String("name", manifest.Name),
				helpers.String("status", status))
			return fmt.Errorf("failed to update CVE summary stub in storage: %w", retryErr)
		}
		logger.L().Debug("updated CVE summary stub in storage",
			helpers.String("name", manifest.Name),
			helpers.String("status", status))
	case err != nil:
		logger.L().Debug("failed to store CVE summary stub in storage", helpers.Error(err),
			helpers.String("name", manifest.Name),
			helpers.String("status", status))
		return fmt.Errorf("failed to store CVE summary stub in storage: %w", err)
	default:
		logger.L().Debug("stored CVE summary stub in storage",
			helpers.String("name", manifest.Name),
			helpers.String("status", status))
	}
	return nil
}

func (a *APIServerStore) StoreVEX(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest, _ bool) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreVEX")
	defer span.End()

	if cvep.Name == "" {
		logger.L().Debug("skipping storing VEX with empty name")
		return nil
	}

	// Check for an existing container first so the common "VEX already exists" path
	// (every scan after the first one for a given image) goes straight to the cheap
	// update below, instead of paying for building the full VEX document, hashing it,
	// and POSTing it via createVEX only to discard the result on AlreadyExists.
	existing, err := a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, cvep.Name, metav1.GetOptions{})
	// Get returns a non-nil (but empty) object even on error, so success must be
	// tracked explicitly rather than by checking the returned pointer for nil.
	haveExisting := err == nil
	switch {
	case errors.IsNotFound(err):
		err = a.createVEX(ctx, cve, cvep)
		switch {
		case err == nil:
			logger.L().Debug("stored VEX in storage", helpers.String("name", cvep.Name))
			return nil
		case errors.IsAlreadyExists(err):
			// A concurrent writer created the container between our Get and our
			// Create; fall through to the retry-on-conflict update path below
			// instead of surfacing the raw AlreadyExists error.
		default:
			logger.L().Debug("failed to store VEX in storage", helpers.Error(err),
				helpers.String("name", cvep.Name))
			return fmt.Errorf("failed to store VEX in storage: %w", err)
		}
	case err != nil:
		logger.L().Debug("failed to get VEX from storage", helpers.Error(err),
			helpers.String("name", cvep.Name))
		return fmt.Errorf("failed to get VEX from storage: %w", err)
	}

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Reuse the object already fetched above on the first attempt, so the common
		// "VEX already exists" path only costs a single Get. Any retry (after a real
		// conflict) forces a fresh Get for the latest resourceVersion.
		vexContainer := existing
		alreadyHadExisting := haveExisting
		haveExisting = false
		if !alreadyHadExisting {
			// retrieve the latest version before attempting update
			// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
			//
			// NOTE: this must NOT use GetOptions{ResourceVersion: "metadata"} like the
			// sibling Store* methods do. That option returns an ObjectMeta-only object
			// with a zero Spec in kubescape/storage's apiserver, which is safe for the
			// siblings because they overwrite Spec wholesale. updateVEX instead merges
			// into vexContainer.Spec.Statements, so a metadata-only read would silently
			// drop every previously stored statement and then fail when it tries to
			// parse the zeroed Spec.Metadata.Timestamp. The fake clientset used in tests
			// ignores GetOptions entirely, so no test can catch a regression here.
			var getErr error
			vexContainer, getErr = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Get(ctx, cvep.Name, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
		}
		return a.updateVEX(ctx, cve, cvep, vexContainer)
	})
	if retryErr != nil {
		logger.L().Debug("failed to update VEX in storage", helpers.Error(retryErr),
			helpers.String("name", cvep.Name))
		return fmt.Errorf("failed to update VEX in storage: %w", retryErr)
	}
	logger.L().Debug("updated VEX in storage", helpers.String("name", cvep.Name))

	return nil
}

func createProductStructForImageAndPackage(imagePullable string, packagePURL string) (*v1beta1.Product, error) {
	imagePullable = strings.TrimPrefix(imagePullable, "docker://")
	imageComponents := strings.Split(imagePullable, "/")
	imageName := imageComponents[len(imageComponents)-1]
	imageRepo := strings.Join(imageComponents[:len(imageComponents)-1], "/")
	// pkg:oci/adservice@sha256%3A45fb8ed886902c0c49e044b1f8870fad61c1022fa23c4943098302a8f1c5b75f?repository_url=gcr.io/google-samples/microservices-demo
	var imageField string
	if imageRepo != "" {
		imageField = fmt.Sprintf("pkg:oci/%s?repository_url=%s", url.PathEscape(imageName), url.PathEscape(imageRepo))
	} else {
		imageField = fmt.Sprintf("pkg:oci/%s", url.PathEscape(imageName))
	}
	product := v1beta1.Product{
		Component: v1beta1.Component{
			ID: imageField,
		},
	}
	product.Subcomponents = append(product.Subcomponents, v1beta1.Subcomponent{
		Component: v1beta1.Component{
			ID: packagePURL,
		},
	})
	return &product, nil
}

// anyPURLMatches reports whether fn returns true for any subcomponent PURL across any
// product in products. This is the shared traversal used by both statementHasPURL and
// the ignored-vulnerability lookup in updateVEX, so both stay correct together if the
// traversal logic ever needs to change.
func anyPURLMatches(products []v1beta1.Product, fn func(purl string) bool) bool {
	for _, p := range products {
		for _, sc := range p.Subcomponents {
			if fn(sc.ID) {
				return true
			}
		}
	}
	return false
}

// statementHasPURL reports whether any subcomponent across any product in products
// matches purl. External VEX statements (Red Hat CSAF, Chainguard OpenVEX) can list
// multiple products/subcomponents per statement, so callers must not assume the match
// is always at Products[0].Subcomponents[0].
func statementHasPURL(products []v1beta1.Product, purl string) bool {
	return anyPURLMatches(products, func(p string) bool { return p == purl })
}

// defaultActionStatement is used when a match does not carry enough fix data to build a
// more specific remediation string.
const defaultActionStatement = "Upgrade the vulnerable component to a version that is not affected"

const (
	defaultLocalImpactStatement      = "Vulnerable component is not loaded into the memory"
	securityExceptionImpactStatement = "Vulnerability was ignored by a SecurityException"
	// cloudExceptionImpactStatement covers a suppression from an exception policy that did
	// not come from a CRD, which today means one delivered by the backend. Those reach
	// ApplySecurityExceptions like any other policy but never go through buildPolicy, so
	// they carry no sourceKind and their ignore rule carries no SourceKind either.
	cloudExceptionImpactStatement = "Vulnerability was ignored by an exception policy"
	// externalIgnoreImpactStatement covers an ignore that did not come from our exception
	// machinery at all. Nothing produces one today, ApplySecurityExceptions being the only
	// writer of IgnoredMatches and Grype being given no VEX documents or ignore rules, but
	// consuming external VEX feeds (#387) is what would.
	externalIgnoreImpactStatement       = "Vulnerability was ignored by an external VEX document or scanner configuration"
	securityExceptionAcceptedRiskAction = "A SecurityException accepted this vulnerability as an affected finding"
)

type ignoredVEXAssessment struct {
	status          v1beta1.Status
	justification   v1beta1.Justification
	impactStatement string
	actionStatement string
	statusNotes     string
}

func ignoredMatchAssessment(m v1beta1.IgnoredMatch) ignoredVEXAssessment {
	assessment := ignoredVEXAssessment{
		status:        v1beta1.Status(vex.StatusNotAffected),
		justification: v1beta1.Justification(vex.VulnerableCodeNotPresent),
	}

	rule, ok := securityExceptionIgnoreRule(m)
	if !ok {
		// No CRD provenance does not make it someone else's. A backend-delivered exception
		// policy suppresses through the same path and leaves a rule with only the
		// vulnerability id on it, so calling that an external VEX document would describe
		// most suppressions wrongly on any cluster using cloud exceptions.
		assessment.impactStatement = externalIgnoreImpactStatement
		if isOwnIgnoreRule(m) {
			assessment.impactStatement = cloudExceptionImpactStatement
		}
		return assessment
	}

	assessment.impactStatement = securityExceptionImpactStatement

	switch strings.TrimSpace(rule.FixState) {
	case string(sev1beta1.VulnerabilityStatusFixed):
		assessment.status = v1beta1.Status(sev1beta1.VulnerabilityStatusFixed)
		assessment.justification = ""
		assessment.impactStatement = ""
		assessment.statusNotes = ignoredMatchStatusNotes(rule)
	case string(sev1beta1.VulnerabilityStatusAffected):
		assessment.status = v1beta1.Status(vex.StatusAffected)
		assessment.justification = ""
		assessment.impactStatement = ""
		assessment.actionStatement = securityExceptionAcceptedRiskAction
		assessment.statusNotes = ignoredMatchStatusNotes(rule)
	default:
		// Any unrecognized status (including "" and NotAffected) falls back to the safe
		// not_affected-shaped assessment.
		if j := strings.TrimSpace(rule.Justification); j != "" {
			assessment.justification = v1beta1.Justification(j)
		}
		if impact := strings.TrimSpace(rule.ImpactStatement); impact != "" {
			assessment.impactStatement = impact
		}
	}

	return assessment
}

// securityExceptionIgnoreRule extracts the specific rule generated by a SecurityException.
// This is distinct from the adapter's isExceptionSourcedIgnore because it strictly
// matches the SourceKind rather than inferring provenance from rule shape, ensuring
// that only explicit CRD-driven rules receive the SecurityException impact statement.
// isOwnIgnoreRule reports whether an ignored match was suppressed by our own exception
// machinery. buildIgnoreRule writes exactly one rule per suppression and never sets Package,
// while Grype expresses its own ignore rules in terms of a package, so one carrying a package
// did not come from us.
func isOwnIgnoreRule(m v1beta1.IgnoredMatch) bool {
	if len(m.AppliedIgnoreRules) != 1 {
		return false
	}
	return m.AppliedIgnoreRules[0].Package == nil
}

func securityExceptionIgnoreRule(m v1beta1.IgnoredMatch) (v1beta1.IgnoreRule, bool) {
	for _, rule := range m.AppliedIgnoreRules {
		switch rule.SourceKind {
		case "SecurityException", "ClusterSecurityException":
			return rule, true
		}
	}
	return v1beta1.IgnoreRule{}, false
}

func ignoredMatchStatusNotes(rule v1beta1.IgnoreRule) string {
	parts := make([]string, 0, 2)
	if j := strings.TrimSpace(rule.Justification); j != "" {
		parts = append(parts, "justification: "+j)
	}
	if impact := strings.TrimSpace(rule.ImpactStatement); impact != "" {
		parts = append(parts, "impact: "+impact)
	}
	return strings.Join(parts, "; ")
}

// newLocalStatement builds the VEX statement kubevuln writes for a match, in the baseline
// not_affected shape. createVEX and updateVEX each build one for a match and one for an
// ignored match, and all four spelled it out; this is the one place that shape is defined,
// so a field added to it cannot reach three sites and miss the fourth.
//
// A caller recording a suppression overwrites the baseline with applyIgnoredMatchAssessment,
// which sets every one of the five fields it touches.
func newLocalStatement(m v1beta1.Match, imagePullable string) (v1beta1.Statement, error) {
	product, err := createProductStructForImageAndPackage(imagePullable, m.Artifact.PURL)
	if err != nil {
		return v1beta1.Statement{}, err
	}

	var aliases []string
	for _, alias := range m.RelatedVulnerabilities {
		aliases = append(aliases, alias.ID)
	}

	return v1beta1.Statement{
		ID: fmt.Sprintf("https://kubescape.io/vex/statement/%s/%s", url.PathEscape(m.Vulnerability.ID), url.PathEscape(m.Artifact.PURL)),
		Vulnerability: v1beta1.VexVulnerability{
			ID:          m.Vulnerability.DataSource,
			Name:        m.Vulnerability.ID,
			Description: m.Vulnerability.Description,
			Aliases:     aliases,
		},
		Products:        []v1beta1.Product{*product},
		Status:          v1beta1.Status(vex.StatusNotAffected),
		Justification:   v1beta1.Justification(vex.VulnerableCodeNotPresent),
		ImpactStatement: defaultLocalImpactStatement,
	}, nil
}

func applyIgnoredMatchAssessment(stmt *v1beta1.Statement, assessment ignoredVEXAssessment) {
	stmt.Status = assessment.status
	stmt.Justification = assessment.justification
	stmt.ImpactStatement = assessment.impactStatement
	stmt.ActionStatement = assessment.actionStatement
	stmt.StatusNotes = assessment.statusNotes
}

// buildActionStatement returns a remediation string for an affected VEX statement. When the
// match reports a fixed state with known fix versions, it names them; otherwise it falls back
// to defaultActionStatement.
func buildActionStatement(v v1beta1.Match) string {
	if v.Vulnerability.Fix.State == "fixed" && len(v.Vulnerability.Fix.Versions) > 0 {
		return upgradeActionStatementPrefix(v.Artifact.PURL) + strings.Join(v.Vulnerability.Fix.Versions, " or ")
	}
	return defaultActionStatement
}

// hasSwappedVulnerabilityFields reports whether a statement carries the CVE in
// Vulnerability.ID and the data source URL in Name, the mapping used before it was corrected
// to match createVEX. Both the adoption below and the normalization that follows it key off
// this, so they cannot disagree about which statements are written the old way round.
func hasSwappedVulnerabilityFields(v v1beta1.VexVulnerability) bool {
	return !strings.Contains(v.ID, "://") && (v.Name == "" || strings.Contains(v.Name, "://"))
}

// vulnerabilityCVEName returns the CVE identifier a statement carries, from whichever field
// holds it. Statements written before #595 can be affected by both legacy shapes at once, no
// ID and the swapped mapping, and stamping an ID needs the CVE rather than whatever happens
// to be in Name.
func vulnerabilityCVEName(v v1beta1.VexVulnerability) string {
	if hasSwappedVulnerabilityFields(v) {
		return v.ID
	}
	return v.Name
}

// upgradeActionStatementPrefix is the fixed part of the action statement
// buildActionStatement writes when the fix versions are known. It is shared with
// isOwnActionStatement so the two cannot drift on what our own wording looks like.
func upgradeActionStatementPrefix(purl string) string {
	return fmt.Sprintf("Upgrade %s to version ", purl)
}

// isOwnActionStatement reports whether an action statement is one kubevuln writes itself.
//
// markRelevantVulnerabilitiesAsAffectedInVex blanks the impact statement on a statement it
// marks affected and fills this in instead, so on those this is the only wording of ours
// left to recognise. Action statements arrived in #404, ten days before the IDs in #595, so
// a statement written in between has one of these and no ID.
//
// The parameterised form is matched against the statement's own subcomponent rather than as
// a loose prefix, so a feed's text that happens to open the same way does not qualify.
func isOwnActionStatement(actionStatement, purl string) bool {
	if actionStatement == defaultActionStatement {
		return true
	}
	return purl != "" && strings.HasPrefix(actionStatement, upgradeActionStatementPrefix(purl))
}

// localStatementID is the ID kubevuln stamps on statements it authors.
func localStatementID(cveName, purl string) string {
	return fmt.Sprintf("https://kubescape.io/vex/statement/%s/%s", url.PathEscape(cveName), url.PathEscape(purl))
}

// isOwnImpactStatement reports whether an impact statement is one kubevuln writes itself.
// It is the only thing left on a statement we stored before #595 that marks it as ours,
// those having been written without an ID, and the wording is our own rather than anything
// a feed would produce.
func isOwnImpactStatement(impactStatement string) bool {
	switch impactStatement {
	case defaultLocalImpactStatement, securityExceptionImpactStatement:
		return true
	}
	return false
}

func isLocalStatement(id string) bool {
	return strings.HasPrefix(id, "https://kubescape.io/vex/statement/")
}

// vexStatementKey identifies a locally generated VEX statement by the vulnerability it
// covers and the package it applies to. Statements produced by createProductStructForImageAndPackage
// always carry exactly one product with exactly one subcomponent, so this pair uniquely
// locates a statement without rescanning the whole slice.
type vexStatementKey struct {
	name string
	purl string
}

// buildLocalVexStatementIndex indexes the local (scanner-generated) statements in
// statements by vulnerability name and package PURL, once, so callers can replace
// repeated O(n) scans over vexDoc.Statements with O(1) lookups. External statements
// (Red Hat CSAF, Chainguard OpenVEX, ...) are never targeted by the dedup/mark logic
// that consumes this index, so they are skipped. Every product/subcomponent of a local
// statement is indexed, not just the first: locally generated statements normally carry
// exactly one, but nothing prevents one from being expanded to carry more (e.g. a
// statement edited or merged out of band), and statementHasPURL/anyPURLMatches already
// treat that as a valid shape to match against.
//
// A key can map to more than one statement index: some already-persisted VEX documents
// contain duplicate local statements for the same (vulnerability, PURL), predating the
// ID/Name-swap normalization above. The pre-index code scanned every statement on every
// match, so it updated all such duplicates; the index preserves that by collecting every
// matching index instead of keeping only the last one seen.
func buildLocalVexStatementIndex(statements []v1beta1.Statement) map[vexStatementKey][]int {
	idx := make(map[vexStatementKey][]int, len(statements))
	for i, s := range statements {
		if !isLocalStatement(s.ID) {
			continue
		}
		for _, p := range s.Products {
			for _, sc := range p.Subcomponents {
				key := vexStatementKey{name: s.Vulnerability.Name, purl: sc.ID}
				idx[key] = append(idx[key], i)
			}
		}
	}
	return idx
}

func markRelevantVulnerabilitiesAsAffectedInVex(vexDoc *v1beta1.VEX, cvep *domain.CVEManifest, idx map[vexStatementKey][]int) error {
	if cvep == nil || cvep.Content == nil {
		return nil
	}
	// Now change the status of the filtered vulnerabilities to "Affected"
	for _, v := range cvep.Content.Matches {
		indices, ok := idx[vexStatementKey{name: v.Vulnerability.ID, purl: v.Artifact.PURL}]
		if !ok {
			continue
		}
		for _, i := range indices {
			vexDoc.Statements[i].Status = v1beta1.Status(vex.StatusAffected)
			vexDoc.Statements[i].Justification = ""
			vexDoc.Statements[i].ImpactStatement = ""
			vexDoc.Statements[i].ActionStatement = buildActionStatement(v)
			vexDoc.Statements[i].StatusNotes = ""
		}
	}
	return nil
}

func (a *APIServerStore) createVEX(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.createVEX")
	defer span.End()

	imagePullable := cve.Annotations[helpersv1.ImageIDMetadataKey]

	// Timestamp
	timestamp := time.Now().Format(time.RFC3339)

	// Calculate VEX
	vexDoc := v1beta1.VEX{
		Metadata: v1beta1.Metadata{
			Context:     "https://openvex.dev/ns/v0.2.0",
			Author:      "kubescape.io",
			AuthorRole:  "smart vulnerability scanner :-)",
			Timestamp:   timestamp,
			LastUpdated: timestamp,
			Version:     0,
			Tooling:     "kubescape-vulnerability-analyzer",
		},
	}

	// Loop over the Vulnerability struct and add each vulnerability to the VEX document, and
	// add ignored vulnerabilities as not_affected with SecurityException impact statement.
	// Both loops read cve.Content, so both are guarded by the same nil check.
	if cve.Content != nil {
		for _, v := range cve.Content.Matches {
			stmt, err := newLocalStatement(v, imagePullable)
			if err != nil {
				return err
			}
			vexDoc.Statements = append(vexDoc.Statements, stmt)
		}

		for _, v := range cve.Content.IgnoredMatches {
			stmt, err := newLocalStatement(v.Match, imagePullable)
			if err != nil {
				return err
			}
			applyIgnoredMatchAssessment(&stmt, ignoredMatchAssessment(v))
			vexDoc.Statements = append(vexDoc.Statements, stmt)
		}
	}

	// Now change the status of the filtered vulnerabilities to "Affected"
	markIdx := buildLocalVexStatementIndex(vexDoc.Statements)
	err := markRelevantVulnerabilitiesAsAffectedInVex(&vexDoc, &cvep, markIdx)
	if err != nil {
		return err
	}

	_ = markIgnoredVulnerabilitiesInVex(&vexDoc, &cve, markIdx)
	_ = markIgnoredVulnerabilitiesInVex(&vexDoc, &cvep, markIdx)

	calculatedId, err := calculateVexCanonicalHash(vexDoc)
	if err != nil {
		return err
	}

	vexDoc.Metadata.ID = calculatedId

	// Create the VEX container
	vexContainer := v1beta1.OpenVulnerabilityExchangeContainer{
		ObjectMeta: metav1.ObjectMeta{
			Name:        cvep.Name,
			Labels:      cvep.Labels,
			Annotations: cvep.Annotations,
		},
		Spec: vexDoc,
	}

	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Create(ctx, &vexContainer, metav1.CreateOptions{})

	return err
}

func markIgnoredVulnerabilitiesInVex(vexDoc *v1beta1.VEX, cve *domain.CVEManifest, idx map[vexStatementKey][]int) error {
	if cve == nil || cve.Content == nil {
		return nil
	}
	for _, v := range cve.Content.IgnoredMatches {
		indices, ok := idx[vexStatementKey{name: v.Vulnerability.ID, purl: v.Artifact.PURL}]
		if !ok {
			continue
		}
		for _, i := range indices {
			applyIgnoredMatchAssessment(&vexDoc.Statements[i], ignoredMatchAssessment(v))
		}
	}
	return nil
}

func (a *APIServerStore) updateVEX(ctx context.Context, cve domain.CVEManifest, cvep domain.CVEManifest, vexContainer *v1beta1.OpenVulnerabilityExchangeContainer) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.updateVEX")
	defer span.End()

	imagePullable := cve.Annotations[helpersv1.ImageIDMetadataKey]

	// Extend the VEX document with vulnerability data from full vulnerability manifest
	originalVEX := *vexContainer.Spec.DeepCopy()
	vexDoc := *vexContainer.Spec.DeepCopy()

	// Statements we stored before #595 have no ID, that being the change which started
	// setting one. #664 stopped reading an empty ID as ours so that a feed's ID-less
	// statement is not overwritten, which is right, but it also left every statement we
	// wrote before #595 looking like another author's: passed over by the reset loop and by
	// every marking step, and passed over by the dedup too, so a second statement gets
	// appended beside it for the same finding. Stamp the ID we would write today onto the
	// ones carrying wording of ours, which brings them back under management and leaves
	// anything else alone. Both fields are checked: a statement last written while affected
	// had its impact statement blanked and an action statement put in its place, so that is
	// the only wording left on it.
	for i := range vexDoc.Statements {
		s := &vexDoc.Statements[i]
		if s.ID != "" {
			continue
		}
		if len(s.Products) == 0 || len(s.Products[0].Subcomponents) == 0 {
			continue
		}
		purl := s.Products[0].Subcomponents[0].ID
		if !isOwnImpactStatement(s.ImpactStatement) && !isOwnActionStatement(s.ActionStatement, purl) {
			continue
		}
		s.ID = localStatementID(vulnerabilityCVEName(s.Vulnerability), purl)
	}

	// Statements written before the ID/Name mapping was corrected to match createVEX
	// carry the CVE identifier in ID and the data source URL in Name. Normalize them in
	// place so the dedup below (which now keys on Name) also finds these older entries,
	// instead of re-appending a duplicate for every one of them.
	for i, s := range vexDoc.Statements {
		if !isLocalStatement(s.ID) {
			continue
		}
		if hasSwappedVulnerabilityFields(s.Vulnerability) {
			vexDoc.Statements[i].Vulnerability.ID, vexDoc.Statements[i].Vulnerability.Name = s.Vulnerability.Name, s.Vulnerability.ID
		}
	}

	// statementIdx tracks local statements by (vulnerability, package), built once and kept
	// up to date as statements are appended below. It drives the Matches/IgnoredMatches dedup
	// checks and, once the document is fully assembled, the mark-affected/mark-ignored passes,
	// replacing what used to be repeated O(n) scans over vexDoc.Statements with O(1) lookups.
	statementIdx := buildLocalVexStatementIndex(vexDoc.Statements)

	if cve.Content != nil {
		for _, v := range cve.Content.Matches {
			key := vexStatementKey{name: v.Vulnerability.ID, purl: v.Artifact.PURL}
			if _, found := statementIdx[key]; !found {
				// Add the vulnerability to the VEX document
				stmt, err := newLocalStatement(v, imagePullable)
				if err != nil {
					return err
				}
				vexDoc.Statements = append(vexDoc.Statements, stmt)
				statementIdx[key] = append(statementIdx[key], len(vexDoc.Statements)-1)
			}
		}

		for _, v := range cve.Content.IgnoredMatches {
			// Only our own statements count as already present. An external one is
			// another author's assessment, and every step below that maintains a
			// statement (mark-affected, mark-ignored, reset-to-baseline) is local-only,
			// so treating it as ours would drop kubescape's assessment of this
			// vulnerability from the document instead of recording it alongside theirs.
			key := vexStatementKey{name: v.Vulnerability.ID, purl: v.Artifact.PURL}
			if _, found := statementIdx[key]; !found {
				stmt, err := newLocalStatement(v.Match, imagePullable)
				if err != nil {
					return err
				}
				applyIgnoredMatchAssessment(&stmt, ignoredMatchAssessment(v))
				vexDoc.Statements = append(vexDoc.Statements, stmt)
				statementIdx[key] = append(statementIdx[key], len(vexDoc.Statements)-1)
			}
		}
	}

	// ignoredMap drives the "reset every statement" pass below; guarded the same way as the
	// Matches/IgnoredMatches loops above, since it reads the same cve.Content.
	ignoredMap := make(map[string]ignoredVEXAssessment)
	if cve.Content != nil {
		for _, v := range cve.Content.IgnoredMatches {
			ignoredMap[v.Vulnerability.ID+v.Artifact.PURL] = ignoredMatchAssessment(v)
		}
	}

	// Reset every statement back to the baseline "not affected" status before
	// reapplying the current filtered manifest.
	for i := range vexDoc.Statements {
		// Only reset statements generated by the local scanner.
		// External statements with their own ID are left intact.
		if !isLocalStatement(vexDoc.Statements[i].ID) {
			continue
		}

		vexDoc.Statements[i].Status = v1beta1.Status(vex.StatusNotAffected)
		vexDoc.Statements[i].Justification = v1beta1.Justification(vex.VulnerableCodeNotPresent)
		vexDoc.Statements[i].ImpactStatement = defaultLocalImpactStatement
		vexDoc.Statements[i].ActionStatement = ""
		vexDoc.Statements[i].StatusNotes = ""

		var assessment ignoredVEXAssessment
		isIgnored := anyPURLMatches(vexDoc.Statements[i].Products, func(purl string) bool {
			if ignoredAssessment, ok := ignoredMap[vexDoc.Statements[i].Vulnerability.Name+purl]; ok {
				assessment = ignoredAssessment
				return true
			}
			return false
		})

		if isIgnored {
			applyIgnoredMatchAssessment(&vexDoc.Statements[i], assessment)
		}
	}

	// Now change the status of the filtered vulnerabilities to "Affected". statementIdx is
	// still valid here: the reset loop above only rewrites fields on existing statements, it
	// never appends or reorders them.
	err := markRelevantVulnerabilitiesAsAffectedInVex(&vexDoc, &cvep, statementIdx)
	if err != nil {
		return err
	}

	_ = markIgnoredVulnerabilitiesInVex(&vexDoc, &cve, statementIdx)
	_ = markIgnoredVulnerabilitiesInVex(&vexDoc, &cvep, statementIdx)

	mergedAnnotations := mergeMaps(maps.Clone(vexContainer.Annotations), cvep.Annotations)
	mergedLabels := mergeMaps(maps.Clone(vexContainer.Labels), cvep.Labels)
	if vexDocumentsEqualIgnoringUpdateMetadata(originalVEX, vexDoc) &&
		maps.Equal(vexContainer.Annotations, mergedAnnotations) &&
		maps.Equal(vexContainer.Labels, mergedLabels) {
		return nil
	}

	// Update the VEX document metadata
	vexDoc.Metadata.LastUpdated = time.Now().Format(time.RFC3339)
	vexDoc.Metadata.Version += 1

	calculatedId, err := calculateVexCanonicalHash(vexDoc)
	if err != nil {
		return err
	}

	vexDoc.Metadata.ID = calculatedId

	// Update the VEX container
	vexContainer.Annotations = mergedAnnotations
	vexContainer.Labels = mergedLabels
	vexContainer.Spec = vexDoc
	_, err = a.StorageClient.OpenVulnerabilityExchangeContainers(a.Namespace).Update(ctx, vexContainer, metav1.UpdateOptions{})

	return err
}

func vexDocumentsEqualIgnoringUpdateMetadata(existing, updated v1beta1.VEX) bool {
	existing.LastUpdated = ""
	existing.Version = 0
	existing.ID = ""
	updated.LastUpdated = ""
	updated.Version = 0
	updated.ID = ""

	return reflect.DeepEqual(existing, updated)
}

func calculateVexCanonicalHash(vexDoc v1beta1.VEX) (string, error) {
	// Here's the algo:

	ts, err := time.Parse(time.RFC3339, vexDoc.Timestamp)
	if err != nil {
		return "", err
	}
	docTsStr := ts.UTC().Format(time.RFC3339Nano)
	cString := fmt.Sprintf(":%d:%s:%d:%d:%s", len(docTsStr), docTsStr, vexDoc.Version, len(vexDoc.Author), vexDoc.Author)

	stmts := make([]v1beta1.Statement, len(vexDoc.Statements))
	copy(stmts, vexDoc.Statements)
	sortVexStatements(stmts, ts)

	//nolint:gocritic
	for _, s := range stmts {
		// 5a. Vulnerability
		cString += cstringFromVulnerability(s.Vulnerability)
		// 5b. Status + Justification
		cString += fmt.Sprintf(":%d:%s:%d:%s", len(s.Status), s.Status, len(s.Justification), s.Justification)
		// 5c. Statement time, in RFC3339Nano. If it exists, if not the doc's (malformed timestamps fallback to doc time)
		stmtTs, err := time.Parse(time.RFC3339, s.Timestamp)
		if err != nil {
			stmtTs = ts
		}
		stmtTsStr := stmtTs.UTC().Format(time.RFC3339Nano)
		cString += fmt.Sprintf(":%d:%s", len(stmtTsStr), stmtTsStr)
		// 5d. Sorted product strings
		cString += cstringFromProducts(s.Products)
	}

	h := sha256.New()
	if _, err := h.Write([]byte(cString)); err != nil {
		return "", fmt.Errorf("hashing canonicalization string: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func cstringFromProducts(products []v1beta1.Product) string {
	var prods []string
	for _, p := range products {
		prodString := cstringFromComponent(p.Component)
		if len(p.Subcomponents) > 0 {
			subprods := make([]string, 0, len(p.Subcomponents))
			for _, sc := range p.Subcomponents {
				subprods = append(subprods, cstringFromComponent(sc.Component))
			}
			sort.Strings(subprods)
			for _, scStr := range subprods {
				prodString += fmt.Sprintf(":sub:%d:%s", len(scStr), scStr)
			}
		}
		prods = append(prods, prodString)
	}
	sort.Strings(prods)
	var result string
	for _, pStr := range prods {
		result += fmt.Sprintf(":prod:%d:%s", len(pStr), pStr)
	}
	return result
}

// sortVexStatements sorts a slice of VEX statements deterministically in place.
// Callers that need to preserve their original slice order must pass a clone.
//
// Ordering prioritizes:
//  1. Vulnerability.Name (fast-path filter across different CVEs)
//  2. Full canonical vulnerability string (Name, ID, and sorted Aliases)
//  3. Statement timestamp (falling back to document timestamp if omitted or malformed)
//  4. Status
//  5. Justification
//  6. Canonical product strings (including sorted components, subcomponents, hashes, and identifiers)
//  7. Statement ID
//  8. ImpactStatement, ActionStatement, and StatusNotes
func sortVexStatements(stmts []v1beta1.Statement, documentTimestamp time.Time) {
	sort.SliceStable(stmts, func(i, j int) bool {
		// 1. Compare Vulnerability.Name as a fast path before computing full vulnerability strings
		vulnComparison := strings.Compare(stmts[i].Vulnerability.Name, stmts[j].Vulnerability.Name)
		if vulnComparison != 0 {
			return vulnComparison < 0
		}

		// 2. Full vulnerability comparison including ID and sorted Aliases
		vulnCstringComparison := strings.Compare(cstringFromVulnerability(stmts[i].Vulnerability), cstringFromVulnerability(stmts[j].Vulnerability))
		if vulnCstringComparison != 0 {
			return vulnCstringComparison < 0
		}

		// 3. Statement timestamp; intentionally fallback to document timestamp if empty or invalid RFC3339
		iTime, err := time.Parse(time.RFC3339, stmts[i].Timestamp)
		if err != nil {
			iTime = documentTimestamp
		}

		jTime, err := time.Parse(time.RFC3339, stmts[j].Timestamp)
		if err != nil {
			jTime = documentTimestamp
		}

		if !iTime.Equal(jTime) {
			return iTime.Before(jTime)
		}

		// 4. Status
		if c := strings.Compare(string(stmts[i].Status), string(stmts[j].Status)); c != 0 {
			return c < 0
		}

		// 5. Justification
		if c := strings.Compare(string(stmts[i].Justification), string(stmts[j].Justification)); c != 0 {
			return c < 0
		}

		// 6. Products and subcomponents
		if c := strings.Compare(cstringFromProducts(stmts[i].Products), cstringFromProducts(stmts[j].Products)); c != 0 {
			return c < 0
		}

		// 7. Statement ID
		if c := strings.Compare(stmts[i].ID, stmts[j].ID); c != 0 {
			return c < 0
		}

		// 8. Remaining metadata fields
		if c := strings.Compare(stmts[i].ImpactStatement, stmts[j].ImpactStatement); c != 0 {
			return c < 0
		}

		if c := strings.Compare(stmts[i].ActionStatement, stmts[j].ActionStatement); c != 0 {
			return c < 0
		}

		return stmts[i].StatusNotes < stmts[j].StatusNotes
	})
}

func cstringFromVulnerability(v v1beta1.VexVulnerability) string {
	cString := fmt.Sprintf(":%d:%s:%d:%s", len(v.ID), v.ID, len(v.Name), v.Name)
	if len(v.Aliases) > 0 {
		list := make([]string, len(v.Aliases))
		copy(list, v.Aliases)
		sort.Strings(list)
		for _, alias := range list {
			cString += fmt.Sprintf(":%d:%s", len(alias), alias)
		}
	}
	return cString
}

// cstringFromComponent renders one component into the canonicalization string. Both maps are
// walked in sorted key order because Go randomizes map iteration, and fields are length-prefixed
// and tagged to prevent delimiter collisions. This feeds the document's canonical hash, which
// becomes its Metadata.ID: the same content has to render the same string every time or the
// document changes identity between runs for no reason.
//
// Statements kubevuln writes itself carry only an ID (see createProductStructForImageAndPackage),
// so both maps are empty today and the order never showed. An ingested OpenVEX component
// routinely carries several identifiers and hashes, which is where it would.
func cstringFromComponent(c v1beta1.Component) string {
	s := fmt.Sprintf(":%d:%s", len(c.ID), c.ID)

	algos := make([]string, 0, len(c.Hashes))
	for algo := range c.Hashes {
		algos = append(algos, string(algo))
	}
	sort.Strings(algos)
	for _, algo := range algos {
		hashVal := string(c.Hashes[v1beta1.Algorithm(algo)])
		s += fmt.Sprintf(":h:%d:%s:%d:%s", len(algo), algo, len(hashVal), hashVal)
	}

	types := make([]string, 0, len(c.Identifiers))
	for t := range c.Identifiers {
		types = append(types, string(t))
	}
	sort.Strings(types)
	for _, t := range types {
		idVal := c.Identifiers[v1beta1.IdentifierType(t)]
		s += fmt.Sprintf(":i:%d:%s:%d:%s", len(t), t, len(idVal), idVal)
	}

	return s
}

func (a *APIServerStore) GetSBOM(ctx context.Context, name, SBOMCreatorVersion string) (domain.SBOM, error) {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.GetSBOM")
	defer span.End()
	if name == "" {
		logger.L().Debug("empty name provided, skipping SBOM retrieval")
		return domain.SBOM{}, nil
	}
	manifest, err := a.StorageClient.SBOMSyfts(a.Namespace).Get(ctx, name, metav1.GetOptions{})
	switch {
	case errors.IsNotFound(err):
		logger.L().Debug("SBOM manifest not found in storage",
			helpers.String("name", name))
		return domain.SBOM{}, nil
	case err != nil:
		return domain.SBOM{}, fmt.Errorf("failed to get SBOM from apiserver: %w", err)
	}
	// Discard the manifest if it was created by a different version of the scanner, in
	// either direction. A manifest older than SBOMCreatorVersion may predate a schema or
	// content change the caller now relies on; a manifest newer than SBOMCreatorVersion may
	// carry one the caller isn't known to handle yet (e.g. one replica of a rolling
	// deployment/rollback writes it, and a different-versioned replica serving the same
	// image slug reads it back next). Comparing only for "older" let the newer case through
	// as if it were fresh (see #768).
	if semver.Compare(manifest.Spec.Metadata.Tool.Version, SBOMCreatorVersion) != 0 {
		logger.L().Debug("discarding SBOM with mismatched scanner version",
			helpers.String("name", name),
			helpers.String("manifest scanner version", manifest.Spec.Metadata.Tool.Version),
			helpers.String("wanted scanner version", SBOMCreatorVersion))
		result := domain.SBOM{
			Name:               name,
			Annotations:        manifest.Annotations,
			Labels:             manifest.Labels,
			SBOMCreatorVersion: manifest.Spec.Metadata.Tool.Version,
			Content:            &manifest.Spec.Syft,
		}
		if status, ok := manifest.Annotations[helpersv1.StatusMetadataKey]; ok {
			result.Status = status
		}
		return result, domain.ErrOutdatedSBOM
	}
	result := domain.SBOM{
		Name:               name,
		Annotations:        manifest.Annotations,
		Labels:             manifest.Labels,
		// The manifest's own recorded version, not the caller's requested SBOMCreatorVersion:
		// semver.Compare treats build-metadata differences as equal, so the two can still
		// differ as strings even when the check above passes.
		SBOMCreatorVersion: manifest.Spec.Metadata.Tool.Version,
		Content:            &manifest.Spec.Syft,
	}
	if status, ok := manifest.Annotations[helpersv1.StatusMetadataKey]; ok {
		result.Status = status
	}
	logger.L().Debug("got SBOM from storage",
		helpers.String("name", name))
	return result, nil
}

func (a *APIServerStore) StoreSBOM(ctx context.Context, sbom domain.SBOM, isFiltered bool) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.StoreSBOM")
	defer span.End()

	if sbom.Name == "" {
		logger.L().Debug("skipping storing SBOM with empty name")
		return nil
	}
	manifest := v1beta1.SBOMSyft{
		ObjectMeta: metav1.ObjectMeta{
			Name:        sbom.Name,
			Annotations: sbom.Annotations,
			Labels:      sbom.Labels,
		},
		Spec: v1beta1.SBOMSyftSpec{
			Metadata: v1beta1.SPDXMeta{
				Tool: v1beta1.ToolMeta{
					Name:    sbom.SBOMCreatorName,
					Version: sbom.SBOMCreatorVersion,
				},
				Report: v1beta1.ReportMeta{
					CreatedAt: metav1.Now().Rfc3339Copy(),
				},
			},
		},
		Status: v1beta1.SBOMSyftStatus{}, // TODO move timeout information here
	}

	if sbom.Content != nil {
		manifest.Spec.Syft = *sbom.Content
	}
	if manifest.Annotations == nil {
		manifest.Annotations = map[string]string{}
	}
	manifest.Annotations[helpersv1.StatusMetadataKey] = sbom.Status // for the moment stored as an annotation
	if isFiltered {
		filtered := convertToFilteredSBOM(&manifest)
		return createOrUpdate(ctx, a.StorageClient.SBOMSyftFiltereds(a.Namespace), "filtered SBOM", sbom.Name, filtered,
			func(existing *v1beta1.SBOMSyftFiltered) {
				existing.Annotations = mergeMaps(existing.Annotations, filtered.Annotations)
				existing.Labels = mergeMaps(existing.Labels, filtered.Labels)
				existing.Spec = filtered.Spec
			})
	}
	return createOrUpdate(ctx, a.StorageClient.SBOMSyfts(a.Namespace), "SBOM", sbom.Name, &manifest,
		func(existing *v1beta1.SBOMSyft) {
			existing.Annotations = mergeMaps(existing.Annotations, manifest.Annotations)
			existing.Labels = mergeMaps(existing.Labels, manifest.Labels)
			existing.Spec = manifest.Spec
		})
}

func (a *APIServerStore) DeleteSBOM(ctx context.Context, name string) error {
	_, span := otel.Tracer("").Start(ctx, "APIServerStore.DeleteSBOM")
	defer span.End()

	var deleteErr error

	// Delete unfiltered SBOM
	err := a.StorageClient.SBOMSyfts(a.Namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		logger.L().Ctx(ctx).Warning("failed to delete SBOM", helpers.Error(err), helpers.String("name", name))
		deleteErr = err
	}

	// Delete filtered SBOM
	err = a.StorageClient.SBOMSyftFiltereds(a.Namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		logger.L().Ctx(ctx).Warning("failed to delete filtered SBOM", helpers.Error(err), helpers.String("name", name))
		if deleteErr == nil {
			deleteErr = err
		}
	}

	return deleteErr
}

// objectStore is the part of a generated client this needs. The generated interfaces are
// nominally distinct per resource but identical in shape, so each satisfies this for its own
// object type.
type objectStore[T any] interface {
	Create(ctx context.Context, obj T, opts metav1.CreateOptions) (T, error)
	Get(ctx context.Context, name string, opts metav1.GetOptions) (T, error)
	Update(ctx context.Context, obj T, opts metav1.UpdateOptions) (T, error)
}

// createOrUpdate stores obj, falling back to a read-modify-write when the object is already
// there. merge carries whatever the caller wants kept onto the stored object; it runs inside
// the retry, against a freshly read object each time, since a conflict means someone else
// wrote in between and the merge has to happen again on top of that.
//
// kind names the object in the logs and errors ("SBOM", "filtered SBOM").
// extra are appended to every log line this emits, for callers that carry an additional
// field on them. name is the object's own name and is what the Get inside the retry uses,
// so it is the one thing every line here reports about which object is meant.
func createOrUpdate[T any](ctx context.Context, store objectStore[T], kind, name string, obj T, merge func(existing T), extra ...helpers.IDetails) error {
	_, err := store.Create(ctx, obj, metav1.CreateOptions{})
	switch {
	case errors.IsAlreadyExists(err):
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			// retrieve the latest version before attempting update
			// RetryOnConflict uses exponential backoff to avoid exhausting the apiserver
			existing, getErr := store.Get(ctx, name, metav1.GetOptions{ResourceVersion: "metadata"})
			if getErr != nil {
				return getErr
			}
			merge(existing)
			_, updateErr := store.Update(ctx, existing, metav1.UpdateOptions{})
			return updateErr
		})
		if retryErr != nil {
			logger.L().Debug("failed to update "+kind+" in storage", append([]helpers.IDetails{helpers.Error(retryErr), helpers.String("name", name)}, extra...)...)
			return fmt.Errorf("failed to update %s in storage: %w", kind, retryErr)
		}
		logger.L().Debug("updated "+kind+" in storage", append([]helpers.IDetails{helpers.String("name", name)}, extra...)...)
	case err != nil:
		logger.L().Debug("failed to store "+kind+" in storage", append([]helpers.IDetails{helpers.Error(err), helpers.String("name", name)}, extra...)...)
		return fmt.Errorf("failed to store %s in storage: %w", kind, err)
	default:
		logger.L().Debug("stored "+kind+" in storage", append([]helpers.IDetails{helpers.String("name", name)}, extra...)...)
	}
	return nil
}

func convertToFilteredSBOM(sbom *v1beta1.SBOMSyft) *v1beta1.SBOMSyftFiltered {
	return &v1beta1.SBOMSyftFiltered{
		TypeMeta:   sbom.TypeMeta,
		ObjectMeta: sbom.ObjectMeta,
		Spec:       sbom.Spec,
		Status:     sbom.Status,
	}
}

// mergeMaps merges incoming into existing, overwriting existing keys with new values,
// and returns the merged map. Callers MUST use the returned value: when existing is
// nil a fresh map is allocated, so ignoring the return silently drops the merge.
func mergeMaps(existing, incoming map[string]string) map[string]string {
	if existing == nil {
		existing = make(map[string]string, len(incoming))
	}
	for k, v := range incoming {
		existing[k] = v
	}
	return existing
}
