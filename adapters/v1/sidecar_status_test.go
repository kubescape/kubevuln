package v1

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func scannerPod(terminated *corev1.ContainerStateTerminated, restarted bool) *corev1.Pod {
	status := corev1.ContainerStatus{Name: DefaultScannerContainerName}
	if terminated != nil {
		if restarted {
			status.LastTerminationState = corev1.ContainerState{Terminated: terminated}
			status.State = corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
		} else {
			status.State = corev1.ContainerState{Terminated: terminated}
		}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "kubevuln-0", Namespace: "kubescape"},
		Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "kubevuln"}, status}},
	}
}

func newTestPodScannerStatus(t *testing.T, pod *corev1.Pod) (*PodScannerStatus, *fake.Clientset) {
	t.Helper()
	clientset := fake.NewSimpleClientset(pod)
	status := NewPodScannerStatus(clientset.CoreV1().Pods("kubescape"), "kubevuln-0", DefaultScannerContainerName)
	status.wait = 300 * time.Millisecond
	status.poll = 20 * time.Millisecond
	return status, clientset
}

func oomKilledAt(at time.Time) *corev1.ContainerStateTerminated {
	return &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137, FinishedAt: metav1.NewTime(at)}
}

func TestPodScannerStatus_OOMKilledBetween(t *testing.T) {
	// The call ran from 12:00:00.300 to 12:00:05.079; finishedAt has whole seconds.
	start := time.Date(2026, 10, 14, 12, 0, 0, 300_000_000, time.UTC)
	end := start.Add(4*time.Second + 779*time.Millisecond)
	tests := []struct {
		name       string
		terminated *corev1.ContainerStateTerminated
		restarted  bool
		want       bool
	}{
		{name: "OOM kill during the call, container restarted", terminated: oomKilledAt(start.Add(3 * time.Second)), restarted: true, want: true},
		{name: "OOM kill during the call, container still down", terminated: oomKilledAt(start.Add(3 * time.Second)), want: true},
		{name: "OOM kill in the second the call started", terminated: oomKilledAt(start.Truncate(time.Second)), restarted: true, want: true},
		{name: "OOM kill in the second the call ended", terminated: oomKilledAt(end.Truncate(time.Second)), restarted: true, want: true},
		{name: "OOM kill from before the call", terminated: oomKilledAt(start.Add(-time.Minute)), restarted: true},
		{name: "OOM kill after the call had already failed", terminated: oomKilledAt(end.Truncate(time.Second).Add(time.Second)), restarted: true},
		{name: "a plain termination during the call is not an OOM kill", terminated: &corev1.ContainerStateTerminated{Reason: "Error", ExitCode: 143, FinishedAt: metav1.NewTime(start.Add(time.Second))}, restarted: true},
		{name: "no termination recorded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _ := newTestPodScannerStatus(t, scannerPod(tt.terminated, tt.restarted))
			got, err := status.OOMKilledBetween(context.Background(), start, end)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPodScannerStatus_WaitsForTheKubeletToPublishAnInWindowDeath(t *testing.T) {
	start := time.Now()
	end := start.Add(2 * time.Second)
	status, clientset := newTestPodScannerStatus(t, scannerPod(nil, false))

	go func() {
		time.Sleep(60 * time.Millisecond)
		_, err := clientset.CoreV1().Pods("kubescape").UpdateStatus(context.Background(), scannerPod(oomKilledAt(start.Add(time.Second)), true), metav1.UpdateOptions{})
		assert.NoError(t, err)
	}()

	got, err := status.OOMKilledBetween(context.Background(), start, end)
	require.NoError(t, err)
	assert.True(t, got)
}

func TestPodScannerStatus_DoesNotWaitForALaterDeath(t *testing.T) {
	start := time.Now()
	end := start.Add(2 * time.Second)
	status, clientset := newTestPodScannerStatus(t, scannerPod(nil, false))

	go func() {
		time.Sleep(60 * time.Millisecond)
		_, err := clientset.CoreV1().Pods("kubescape").UpdateStatus(context.Background(), scannerPod(oomKilledAt(end.Add(10*time.Second)), true), metav1.UpdateOptions{})
		assert.NoError(t, err)
	}()

	got, err := status.OOMKilledBetween(context.Background(), start, end)
	require.NoError(t, err)
	assert.False(t, got, "a death after the call returned cannot explain its failure")
}

func TestPodScannerStatus_ErrorsWhenTheContainerIsUnknown(t *testing.T) {
	status, _ := newTestPodScannerStatus(t, scannerPod(nil, false))
	status.container = "no-such-container"
	_, err := status.OOMKilledBetween(context.Background(), time.Now(), time.Now())
	require.Error(t, err)
	require.Error(t, status.Probe(context.Background()))
}

func TestPodScannerStatus_ProbeReadsThePod(t *testing.T) {
	status, _ := newTestPodScannerStatus(t, scannerPod(nil, false))
	require.NoError(t, status.Probe(context.Background()))
	status.pod = "no-such-pod"
	require.Error(t, status.Probe(context.Background()))
}

func TestPodScannerStatus_IgnoresTheCallersCancellation(t *testing.T) {
	start := time.Now()
	status, _ := newTestPodScannerStatus(t, scannerPod(oomKilledAt(start.Add(time.Second)), true))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := status.OOMKilledBetween(ctx, start, start.Add(2*time.Second))
	require.NoError(t, err)
	assert.True(t, got, "the scan context is usually done by the time the transport is lost")
}
