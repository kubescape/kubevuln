package adapters

import (
	"context"
	"errors"
	"testing"

	"github.com/armosec/armoapi-go/scanfailure"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/assert"
)

func TestMockPlatform_GetCVEExceptions(t *testing.T) {
	m := NewMockPlatform(true, nil)
	_, _, err := m.GetCVEExceptions(context.Background())
	assert.NoError(t, err)
}

func TestMockPlatform_SendStatus(t *testing.T) {
	m := NewMockPlatform(true, nil)
	ctx := context.TODO()
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})
	err := m.SendStatus(ctx, domain.Done)
	assert.NoError(t, err)
}

func TestMockPlatform_SubmitCVE(t *testing.T) {
	m := NewMockPlatform(true, nil)
	ctx := context.TODO()
	err := m.SubmitCVE(ctx, domain.CVEManifest{}, domain.CVEManifest{})
	assert.NoError(t, err)
}

func TestMockPlatform_ReportError(t *testing.T) {
	m := NewMockPlatform(true, nil)
	err := m.ReportError(context.TODO(), errors.New("boom"))
	assert.NoError(t, err)
}

func TestMockPlatform_ReportScanFailure(t *testing.T) {
	m := NewMockPlatform(true, nil)
	err := m.ReportScanFailure(context.TODO(), scanfailure.ScanFailureCVE, "wlid", errors.New("boom"))
	assert.NoError(t, err)
}
