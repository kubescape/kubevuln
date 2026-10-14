package v1

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	// DefaultScannerContainerName is the sidecar container name the Helm chart uses.
	DefaultScannerContainerName = "sbom-scanner"
	// oomKilledReason is the termination reason the kubelet records for a container the
	// kernel killed for exceeding its memory limit.
	oomKilledReason = "OOMKilled"
	// statusWait bounds how long the kubelet is given to report a termination the client
	// already observed as a lost transport.
	statusWait = 15 * time.Second
	statusPoll = 500 * time.Millisecond
)

// PodScannerStatus answers from the container statuses of the pod the adapter runs in.
type PodScannerStatus struct {
	pods      corev1client.PodInterface
	pod       string
	container string
	wait      time.Duration
	poll      time.Duration
}

var _ ScannerStatus = (*PodScannerStatus)(nil)

func NewPodScannerStatus(pods corev1client.PodInterface, pod, container string) *PodScannerStatus {
	return &PodScannerStatus{pods: pods, pod: pod, container: container, wait: statusWait, poll: statusPoll}
}

// OOMKilledSince reports whether the scanner container's latest termination ended at or
// after since and was an OOM kill. The kubelet reports terminations with a delay, so the
// pod is re-read for a bounded time until a termination from that period shows up; if none
// does, the answer is no.
func (p *PodScannerStatus) OOMKilledSince(ctx context.Context, since time.Time) (bool, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.wait)
	defer cancel()
	// FinishedAt carries whole seconds.
	since = since.Truncate(time.Second)
	for {
		terminated, err := p.latestTermination(ctx)
		if err != nil {
			return false, err
		}
		if terminated != nil && !terminated.FinishedAt.Time.Before(since) {
			return terminated.Reason == oomKilledReason, nil
		}
		select {
		case <-ctx.Done():
			return false, nil
		case <-time.After(p.poll):
		}
	}
}

func (p *PodScannerStatus) latestTermination(ctx context.Context) (*corev1.ContainerStateTerminated, error) {
	pod, err := p.pods.Get(ctx, p.pod, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name != p.container {
			continue
		}
		if cs.State.Terminated != nil {
			return cs.State.Terminated, nil
		}
		return cs.LastTerminationState.Terminated, nil
	}
	return nil, fmt.Errorf("container %q not found in pod %q", p.container, p.pod)
}
