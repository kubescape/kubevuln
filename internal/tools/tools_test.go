package tools

import (
	"k8s.io/apimachinery/pkg/util/validation"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/flock"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageVersion(t *testing.T) {
	assert.True(t, PackageVersion("github.com/anchore/syft") == "unknown") // only works on compiled binaries
}

func TestLabelsFromImageID(t *testing.T) {
	tests := []struct {
		imageID string
		want    map[string]string
	}{
		{
			imageID: "myapp",
			want:    map[string]string{helpersv1.ArtifactTypeMetadataKey: helpersv1.ImageArtifactType, helpersv1.ImageIDMetadataKey: "myapp", helpersv1.ImageNameMetadataKey: "myapp"},
		},
		{
			imageID: "registry.com:8080/myapp",
			want:    map[string]string{helpersv1.ArtifactTypeMetadataKey: helpersv1.ImageArtifactType, helpersv1.ImageIDMetadataKey: "registry-com-8080-myapp", helpersv1.ImageNameMetadataKey: "registry-com-8080-myapp"},
		},
		{
			imageID: "registry.com:8080/myapp:tag",
			want:    map[string]string{helpersv1.ArtifactTypeMetadataKey: helpersv1.ImageArtifactType, helpersv1.ImageIDMetadataKey: "registry-com-8080-myapp-tag", helpersv1.ImageNameMetadataKey: "registry-com-8080-myapp", helpersv1.ImageTagMetadataKey: "tag"},
		},
		{
			imageID: "registry.com:8080/myapp@sha256:be178c0543eb17f5f3043021c9e5fcf30285e557a4fc309cce97ff9ca6182912",
			want:    map[string]string{helpersv1.ArtifactTypeMetadataKey: helpersv1.ImageArtifactType, helpersv1.ImageIDMetadataKey: "registry-com-8080-myapp-sha256-be178c0543eb17f5f3043021c9e5fcf3", helpersv1.ImageNameMetadataKey: "registry-com-8080-myapp"},
		},
		{
			imageID: "registry.com:8080/myapp:tag2@sha256:be178c0543eb17f5f3043021c9e5fcf30285e557a4fc309cce97ff9ca6182912",
			want:    map[string]string{helpersv1.ArtifactTypeMetadataKey: helpersv1.ImageArtifactType, helpersv1.ImageIDMetadataKey: "registry-com-8080-myapp-tag2-sha256-be178c0543eb17f5f3043021c9e", helpersv1.ImageNameMetadataKey: "registry-com-8080-myapp", helpersv1.ImageTagMetadataKey: "tag2"},
		},
		{
			imageID: "quay.io/matthiasb_1/storage@sha256:af6566ed56cbda1e3c2aed9f23da636d41302cccb7de78392c0a6769fb7ba593",
			want:    map[string]string{helpersv1.ArtifactTypeMetadataKey: helpersv1.ImageArtifactType, helpersv1.ImageIDMetadataKey: "quay-io-matthiasb-1-storage-sha256-af6566ed56cbda1e3c2aed9f23da", helpersv1.ImageNameMetadataKey: "quay-io-matthiasb-1-storage"},
		},
		{
			imageID: "602401143452.dkr.ecr.eu-west-1.amazonaws.com/eks/livenessprobe@sha256:f1129c3ed112e3882ee1ac17a40e5e2f4a1c332053c87f84f427b38552f58faa",
			want:    map[string]string{helpersv1.ArtifactTypeMetadataKey: helpersv1.ImageArtifactType, helpersv1.ImageIDMetadataKey: "602401143452-dkr-ecr-eu-west-1-amazonaws-com-eks-livenessprobe", helpersv1.ImageNameMetadataKey: "602401143452-dkr-ecr-eu-west-1-amazonaws-com-eks-livenessprobe"},
		},
		{
			imageID: "quay.io/prometheus/node-exporter@sha256:f2269e73124dd0f60a7d19a2ce1264d33d08a985aed0ee6b0b89d0be470592cd",
			want:    map[string]string{helpersv1.ArtifactTypeMetadataKey: helpersv1.ImageArtifactType, helpersv1.ImageIDMetadataKey: "quay-io-prometheus-node-exporter-sha256-f2269e73124dd0f60a7d19a", helpersv1.ImageNameMetadataKey: "quay-io-prometheus-node-exporter"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.imageID, func(t *testing.T) {
			got := LabelsFromImageID(tt.imageID)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeReference(t *testing.T) {
	type args struct {
		ref string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "image tag only - assuming latest",
			args: args{
				ref: "nginx",
			},
			want: "docker.io/library/nginx:latest",
		},
		{
			name: "image tag",
			args: args{
				ref: "nginx:latest",
			},
			want: "docker.io/library/nginx:latest",
		},
		{
			name: "image sha",
			args: args{
				ref: "nginx@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
			},
			want: "docker.io/library/nginx@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
		},
		{
			name: "image tag sha",
			args: args{
				ref: "nginx:latest@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
			},
			want: "docker.io/library/nginx:latest@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
		},
		{
			name: "repo image tag",
			args: args{
				ref: "index.docker.io/library/nginx:latest",
			},
			want: "docker.io/library/nginx:latest",
		},
		{
			name: "repo image sha",
			args: args{
				ref: "docker.io/library/nginx@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
			},
			want: "docker.io/library/nginx@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
		},
		{
			name: "repo image tag sha",
			args: args{
				ref: "docker.io/library/nginx:latest@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
			},
			want: "docker.io/library/nginx:latest@sha256:73e957703f1266530db0aeac1fd6a3f87c1e59943f4c13eb340bb8521c6041d7",
		},
		{
			name: "quay image tag",
			args: args{
				ref: "quay.io/kubescape/kubevuln:latest",
			},
			want: "quay.io/kubescape/kubevuln:latest",
		},
		{
			name: "quay image sha",
			args: args{
				ref: "quay.io/kubescape/kubevuln@sha256:616d1d4312551b94088deb6ddab232ecabbbff0c289949a0d5f12d4b527c3f8a",
			},
			want: "quay.io/kubescape/kubevuln@sha256:616d1d4312551b94088deb6ddab232ecabbbff0c289949a0d5f12d4b527c3f8a",
		},
		{
			name: "quay image tag sha",
			args: args{
				ref: "quay.io/kubescape/kubevuln:latest@sha256:616d1d4312551b94088deb6ddab232ecabbbff0c289949a0d5f12d4b527c3f8a",
			},
			want: "quay.io/kubescape/kubevuln:latest@sha256:616d1d4312551b94088deb6ddab232ecabbbff0c289949a0d5f12d4b527c3f8a",
		},
		{
			name: "some image other registry",
			args: args{
				ref: "public-registry.systest-ns-na6n:5000/nginx:test",
			},
			want: "public-registry.systest-ns-na6n:5000/nginx:test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NormalizeReference(tt.args.ref), "NormalizeReference(%v)", tt.args.ref)
		})
	}
}

func TestRemoveContainerFromSlug(t *testing.T) {
	tests := []struct {
		name      string
		slug      string
		container string
		want      string
	}{
		{
			name:      "naked pod",
			slug:      "pod-nn-nn-7c1c-a197",
			container: "nn",
			want:      "pod-nn",
		},
		{
			name:      "replicaset",
			slug:      "replicaset-nginx-bf5d5cf98-nginx-b532-f893",
			container: "nginx",
			want:      "replicaset-nginx-bf5d5cf98",
		},
		{
			name:      "tricky",
			slug:      "replicaset-local-path-provisioner-988d74bc-local-path-provisioner-4b6b-20c0",
			container: "local-path-provisioner",
			want:      "replicaset-local-path-provisioner-988d74bc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RemoveContainerFromSlug(tt.slug, tt.container))
		})
	}
}

func TestReferenceMatchForms(t *testing.T) {
	const digest = "sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999"
	tests := []struct {
		name string
		ref  string
		want []string
	}{
		{
			name: "tag only",
			ref:  "docker.io/library/nginx:1.25",
			want: []string{"docker.io/library/nginx:1.25", "docker.io/library/nginx"},
		},
		{
			name: "tag and digest",
			ref:  "docker.io/library/nginx:1.25@" + digest,
			want: []string{"docker.io/library/nginx:1.25@" + digest, "docker.io/library/nginx:1.25", "docker.io/library/nginx"},
		},
		{
			name: "digest only has no tag form",
			ref:  "docker.io/library/nginx@" + digest,
			want: []string{"docker.io/library/nginx@" + digest, "docker.io/library/nginx"},
		},
		{
			name: "registry with port keeps its port",
			ref:  "my-registry.io:5000/team/app:v1",
			want: []string{"my-registry.io:5000/team/app:v1", "my-registry.io:5000/team/app"},
		},
		{
			name: "unparsable reference yields only itself",
			ref:  "not a reference",
			want: []string{"not a reference"},
		},
		{
			name: "empty reference yields only itself",
			ref:  "",
			want: []string{""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ReferenceMatchForms(tt.ref))
		})
	}
}

func TestCleanupStaleTempDirs(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		prefix  string
		age     time.Duration
		wantN   int
		wantErr bool
	}{
		{
			name: "old matching dirs removed, fresh and unrelated kept",
			setup: func(t *testing.T, dir string) {
				old := time.Now().Add(-2 * time.Hour)
				for _, d := range []string{"stereoscope-aaa", "stereoscope-bbb"} {
					require.NoError(t, os.Mkdir(path.Join(dir, d), 0o755))
					require.NoError(t, os.Chtimes(path.Join(dir, d), old, old))
				}
				require.NoError(t, os.Mkdir(path.Join(dir, "stereoscope-new"), 0o755))
				require.NoError(t, os.Mkdir(path.Join(dir, "other-xyz"), 0o755))
				require.NoError(t, os.Chtimes(path.Join(dir, "other-xyz"), old, old))
			},
			prefix: "stereoscope-",
			age:    time.Hour,
			wantN:  2,
		},
		{
			name: "dir clearly younger than threshold is kept",
			setup: func(t *testing.T, dir string) {
				// cutoff = now-1h is computed inside CleanupStaleTempDirs, which runs AFTER
				// this setup, so an exact -1h mtime would already be older than cutoff and be
				// removed. A clear 5s margin inside the threshold makes the "kept" assertion
				// deterministic regardless of clock drift.
				inside := time.Now().Add(-1*time.Hour + 5*time.Second)
				require.NoError(t, os.Mkdir(path.Join(dir, "stereoscope-edge"), 0o755))
				require.NoError(t, os.Chtimes(path.Join(dir, "stereoscope-edge"), inside, inside))
			},
			prefix: "stereoscope-",
			age:    time.Hour,
			wantN:  0,
		},
		{
			name:    "empty dir returns zero and no error",
			setup:   func(t *testing.T, dir string) {},
			prefix:  "stereoscope-",
			age:     time.Hour,
			wantN:   0,
			wantErr: false,
		},
		{
			name: "no matching prefix removes nothing",
			setup: func(t *testing.T, dir string) {
				old := time.Now().Add(-2 * time.Hour)
				require.NoError(t, os.Mkdir(path.Join(dir, "other-dir"), 0o755))
				require.NoError(t, os.Chtimes(path.Join(dir, "other-dir"), old, old))
			},
			prefix: "stereoscope-",
			age:    time.Hour,
			wantN:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(t, dir)
			n, err := CleanupStaleTempDirs(dir, tt.prefix, tt.age)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantN, n)
		})
	}
}

func TestCleanupStaleTempDirs_NonexistentDir(t *testing.T) {
	_, err := CleanupStaleTempDirs(path.Join(t.TempDir(), "does-not-exist"), "stereoscope-", time.Hour)
	require.Error(t, err)
}

func TestStartPeriodicTempDirSweep_RunsAnImmediateSweepSynchronously(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-2 * time.Hour)
	stale := path.Join(dir, "stereoscope-old")
	require.NoError(t, os.Mkdir(stale, 0o755))
	require.NoError(t, os.Chtimes(stale, old, old))

	var mu sync.Mutex
	var calls []int

	stop := make(chan struct{})
	defer close(stop)

	// A long interval means only the immediate, synchronous-before-return sweep can have run
	// by the time this call returns - if it hadn't, the assertions below would be racy.
	StartPeriodicTempDirSweep(stop, dir, "stereoscope-", time.Hour, time.Hour, func(removed int, err error) {
		mu.Lock()
		defer mu.Unlock()
		require.NoError(t, err)
		calls = append(calls, removed)
	})

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []int{1}, calls)
	_, statErr := os.Stat(stale)
	assert.True(t, os.IsNotExist(statErr), "the stale dir present before startup should be reclaimed by the immediate sweep")
}

func TestStartPeriodicTempDirSweep_ReclaimsDirsLeakedAfterStartup(t *testing.T) {
	dir := t.TempDir()
	stop := make(chan struct{})
	defer close(stop)

	removedCh := make(chan int, 8)
	StartPeriodicTempDirSweep(stop, dir, "stereoscope-", 10*time.Millisecond, 10*time.Millisecond, func(removed int, err error) {
		require.NoError(t, err)
		removedCh <- removed
	})

	// the immediate sweep runs against an empty dir
	require.Equal(t, 0, <-removedCh)

	// simulate a leak from an ordinary (non-crash) failure occurring while this process is
	// already running - e.g. a registry pull whose temp dir is created before an error path
	// returns with nothing left to clean it up. A one-time startup sweep would never reclaim
	// this; it must be caught by a later periodic tick.
	old := time.Now().Add(-time.Hour)
	leaked := path.Join(dir, "stereoscope-leaked-midflight")
	require.NoError(t, os.Mkdir(leaked, 0o755))
	require.NoError(t, os.Chtimes(leaked, old, old))

	require.Eventually(t, func() bool {
		_, err := os.Stat(leaked)
		return os.IsNotExist(err)
	}, time.Second, 5*time.Millisecond, "a dir leaked after startup should be reclaimed by a subsequent periodic sweep")
}

func TestStartPeriodicTempDirSweep_StopsTickingOnceStopIsClosed(t *testing.T) {
	dir := t.TempDir()
	stop := make(chan struct{})

	var mu sync.Mutex
	calls := 0
	StartPeriodicTempDirSweep(stop, dir, "stereoscope-", 10*time.Millisecond, 10*time.Millisecond, func(int, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
	})

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls >= 3
	}, time.Second, 5*time.Millisecond, "expected several periodic sweeps before stopping")

	close(stop)
	mu.Lock()
	observedAtStop := calls
	mu.Unlock()

	// long enough for several more ticks to have fired had the goroutine kept running
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, observedAtStop, calls, "no sweep should run after stop is closed")
}

func TestStartPeriodicTempDirSweep_SkipsWhileACallerIsActive(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-2 * time.Hour)
	stale := path.Join(dir, "stereoscope-old")
	require.NoError(t, os.Mkdir(stale, 0o755))
	require.NoError(t, os.Chtimes(stale, old, old))

	end := BeginActiveTempDirUse(dir)
	defer end()

	removedCh := make(chan int, 1)
	stop := make(chan struct{})
	defer close(stop)
	StartPeriodicTempDirSweep(stop, dir, "stereoscope-", time.Hour, time.Hour, func(removed int, err error) {
		require.NoError(t, err)
		removedCh <- removed
	})

	select {
	case removed := <-removedCh:
		t.Fatalf("expected the sweep to be skipped while a caller is active, but onSweep was called with removed=%d", removed)
	case <-time.After(50 * time.Millisecond):
		// no sweep happened, as expected
	}
	_, statErr := os.Stat(stale)
	assert.NoError(t, statErr, "the stale dir should survive a sweep skipped due to an active caller")
}

func TestBeginActiveTempDirUse_EndIsIdempotent(t *testing.T) {
	before := activeTempDirUsers.Load()
	end := BeginActiveTempDirUse(t.TempDir())
	assert.Equal(t, before+1, activeTempDirUsers.Load())
	end()
	end()
	assert.Equal(t, before, activeTempDirUsers.Load(), "calling end twice must not double-decrement")
}

// TestBeginActiveTempDirUse_CrossProcessLeaseVisibleToAnotherHandle is a regression test for the
// cross-container race CodeRabbit flagged on #669: cmd/http and cmd/sbom-scanner run as separate
// OS processes sharing the same /tmp volume, so activeTempDirUsers alone (process-local) can't
// stop one process's sweep from deleting a directory the other is still using. BeginActiveTempDirUse
// acquires a shared flock alongside its in-process counter; opening the same lock file via an
// independent *flock.Flock (simulating a second process, since flock semantics are per open file
// description, not per process) must see it as held for as long as end() hasn't been called.
func TestBeginActiveTempDirUse_CrossProcessLeaseVisibleToAnotherHandle(t *testing.T) {
	dir := t.TempDir()

	end := BeginActiveTempDirUse(dir)

	other := flock.New(activeScanLockPath(dir))
	locked, err := other.TryLock()
	require.NoError(t, err)
	assert.False(t, locked, "an independent handle must not be able to take an exclusive lock while BeginActiveTempDirUse's lease is held")

	end()

	locked, err = other.TryLock()
	require.NoError(t, err)
	assert.True(t, locked, "an independent handle must be able to take the lock once end() releases the lease")
	if locked {
		_ = other.Unlock()
	}
}

// TestStartPeriodicTempDirSweep_SkipsForCrossProcessLease is a regression test for the same race:
// a sweep must be skipped when another process (simulated the same way as above) holds the
// active-scan lease, even though activeTempDirUsers - this process's own counter - is zero.
func TestStartPeriodicTempDirSweep_SkipsForCrossProcessLease(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-2 * time.Hour)
	stale := path.Join(dir, "stereoscope-old")
	require.NoError(t, os.Mkdir(stale, 0o755))
	require.NoError(t, os.Chtimes(stale, old, old))

	otherProcess := flock.New(activeScanLockPath(dir))
	locked, err := otherProcess.TryRLock()
	require.NoError(t, err)
	require.True(t, locked)
	defer func() { _ = otherProcess.Unlock() }()

	require.Zero(t, activeTempDirUsers.Load(), "this process must have no active users of its own for the test to isolate the cross-process path")

	removedCh := make(chan int, 1)
	stop := make(chan struct{})
	defer close(stop)
	StartPeriodicTempDirSweep(stop, dir, "stereoscope-", time.Hour, time.Hour, func(removed int, err error) {
		require.NoError(t, err)
		removedCh <- removed
	})

	select {
	case removed := <-removedCh:
		t.Fatalf("expected the sweep to be skipped while another process holds the active-scan lease, but onSweep was called with removed=%d", removed)
	case <-time.After(50 * time.Millisecond):
		// no sweep happened, as expected
	}
	_, statErr := os.Stat(stale)
	assert.NoError(t, statErr, "the stale dir should survive a sweep skipped due to a cross-process lease holder")
}

func TestStartPeriodicTempDirSweep_NilOnSweepDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	stop := make(chan struct{})
	defer close(stop)

	assert.NotPanics(t, func() {
		StartPeriodicTempDirSweep(stop, dir, "stereoscope-", time.Hour, time.Hour, nil)
	})
}

// LabelsFromImageID drops any label that fails DNS1123 validation, so a value SanitizeLabel
// leaves invalid disappears silently instead of being stored in a degraded form. These are
// the inputs that used to produce one.
func TestSanitizeLabel_AlwaysProducesAValidLabel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "already valid is unchanged", input: "nginx-1-25", want: "nginx-1-25"},
		{name: "offending characters become dashes", input: "nginx:1.25", want: "nginx-1-25"},
		// The reference grammar allows uppercase in a tag, but a DNS1123 label must be lowercase.
		{name: "uppercase tag is lowercased", input: "v1.0-RC1", want: "v1-0-rc1"},
		{name: "mixed case repository", input: "Registry.IO/Team/App", want: "registry-io-team-app"},
		// Adjacent offending characters collapse into several dashes, so stripping one is not enough.
		{name: "several trailing dashes are all stripped", input: "registry.io/team/app:v1_.", want: "registry-io-team-app-v1"},
		{name: "leading offending character is stripped", input: "_myapp", want: "myapp"},
		{name: "leading and trailing together", input: ".myapp.", want: "myapp"},
		{name: "interior dashes are preserved", input: "foo._bar", want: "foo--bar"},
		{name: "all offending characters yield empty", input: "...", want: ""},
		// Not an enumerated set: anything a DNS1123 label may not contain is replaced.
		{name: "unlisted ascii is replaced", input: "foo+bar", want: "foo-bar"},
		{name: "tilde is replaced", input: "foo~bar", want: "foo-bar"},
		{name: "non-ascii is replaced", input: "café", want: "caf"},
		{name: "empty stays empty", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeLabel(tt.input)
			assert.Equal(t, tt.want, got)
			if got != "" {
				assert.Empty(t, validation.IsDNS1123Label(got),
					"SanitizeLabel must return a valid DNS1123 label, got %q", got)
			}
		})
	}
}

// Truncation at 63 characters can land on a dash, which would otherwise leave the label
// ending in one and therefore invalid.
func TestSanitizeLabel_TruncationNeverEndsOnADash(t *testing.T) {
	// 62 characters, so the 63rd is the separator introduced for the dot.
	input := strings.Repeat("a", 62) + ".suffix"

	got := SanitizeLabel(input)

	assert.LessOrEqual(t, len(got), 63)
	assert.Empty(t, validation.IsDNS1123Label(got), "got %q", got)
	assert.Equal(t, strings.Repeat("a", 62), got)
}

// The labels these feed are dropped when invalid, so an image whose tag carries uppercase
// used to lose its image-tag label entirely.
func TestLabelsFromImageID_UppercaseTagIsKept(t *testing.T) {
	labels := LabelsFromImageID("registry.io/team/app:v1.0-RC1")

	assert.Equal(t, "v1-0-rc1", labels[helpersv1.ImageTagMetadataKey])
	assert.Equal(t, "registry-io-team-app", labels[helpersv1.ImageNameMetadataKey])
	for key, value := range labels {
		assert.Empty(t, validation.IsDNS1123Label(value), "label %q has invalid value %q", key, value)
	}
}
