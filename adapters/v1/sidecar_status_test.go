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

func TestPodScannerStatus_OOMKilledSince(t *testing.T) {
	since := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		terminated *corev1.ContainerStateTerminated
		restarted  bool
		want       bool
	}{
		{name: "OOM kill after the scan started, container restarted",
			terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", FinishedAt: metav1.NewTime(since.Add(3 * time.Second))}, restarted: true, want: true},
		{name: "OOM kill after the scan started, container still down",
			terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", FinishedAt: metav1.NewTime(since)}, want: true},
		{name: "OOM kill from before the scan is not evidence",
			terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", FinishedAt: metav1.NewTime(since.Add(-time.Minute))}, restarted: true},
		{name: "a plain termination after the scan started is not an OOM kill",
			terminated: &corev1.ContainerStateTerminated{Reason: "Error", ExitCode: 143, FinishedAt: metav1.NewTime(since.Add(time.Second))}, restarted: true},
		{name: "no termination recorded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _ := newTestPodScannerStatus(t, scannerPod(tt.terminated, tt.restarted))
			got, err := status.OOMKilledSince(context.Background(), since.Add(500*time.Millisecond))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPodScannerStatus_WaitsForTheKubeletToReportTheTermination(t *testing.T) {
	since := time.Now()
	status, clientset := newTestPodScannerStatus(t, scannerPod(nil, false))

	go func() {
		time.Sleep(60 * time.Millisecond)
		pod := scannerPod(&corev1.ContainerStateTerminated{Reason: "OOMKilled", FinishedAt: metav1.NewTime(since.Add(time.Second))}, true)
		_, err := clientset.CoreV1().Pods("kubescape").UpdateStatus(context.Background(), pod, metav1.UpdateOptions{})
		assert.NoError(t, err)
	}()

	got, err := status.OOMKilledSince(context.Background(), since)
	require.NoError(t, err)
	assert.True(t, got)
}

func TestPodScannerStatus_ErrorsWhenTheContainerIsUnknown(t *testing.T) {
	status, _ := newTestPodScannerStatus(t, scannerPod(nil, false))
	status.container = "no-such-container"
	_, err := status.OOMKilledSince(context.Background(), time.Now())
	require.Error(t, err)
}

func TestPodScannerStatus_IgnoresTheCallersCancellation(t *testing.T) {
	since := time.Now()
	status, _ := newTestPodScannerStatus(t, scannerPod(&corev1.ContainerStateTerminated{Reason: "OOMKilled", FinishedAt: metav1.NewTime(since.Add(time.Second))}, true))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := status.OOMKilledSince(ctx, since)
	require.NoError(t, err)
	assert.True(t, got, "the scan context is usually done by the time the transport is lost")
}
