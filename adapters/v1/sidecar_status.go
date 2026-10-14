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

// OOMKilledBetween reports whether the scanner container died of an OOM kill while the
// call ran, that is with a termination that finished between start and end. The bounds are
// compared in whole seconds, the precision FinishedAt has on the wire. The kubelet reports
// terminations with a delay, so the pod is re-read for a bounded time until a termination
// from the interval or later shows up; a death after the interval cannot explain the lost
// call and answers no, as does no termination at all.
func (p *PodScannerStatus) OOMKilledBetween(ctx context.Context, start, end time.Time) (bool, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.wait)
	defer cancel()
	since := start.Truncate(time.Second)
	until := end.Truncate(time.Second)
	for {
		terminated, err := p.latestTermination(ctx)
		if err != nil {
			return false, err
		}
		if terminated != nil && !terminated.FinishedAt.Time.Before(since) {
			if terminated.FinishedAt.Time.After(until) {
				return false, nil
			}
			return terminated.Reason == oomKilledReason, nil
		}
		select {
		case <-ctx.Done():
			return false, nil
		case <-time.After(p.poll):
		}
	}
}

// Probe reads the pod once, so a missing permission shows at startup instead of at the
// first lost scan.
func (p *PodScannerStatus) Probe(ctx context.Context) error {
	_, err := p.latestTermination(ctx)
	return err
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
