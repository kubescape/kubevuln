package v1

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	sysreport "github.com/armosec/logger-go/system-reports/datastructures"
	pkgcautils "github.com/armosec/utils-k8s-go/armometadata"
	wlidpkg "github.com/armosec/utils-k8s-go/wlid"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
)

type ArmoAdapter struct {
	clusterConfig pkgcautils.ClusterConfig
}

var _ ports.Platform = (*ArmoAdapter)(nil)

func NewArmoAdapter(accountID, eventReceiverURL string) *ArmoAdapter {
	return &ArmoAdapter{
		clusterConfig: pkgcautils.ClusterConfig{
			AccountID:            accountID,
			EventReceiverRestURL: eventReceiverURL,
		},
	}
}

const ActionName = "vuln scan"
const ReporterName = "ca-vuln-scan"

var details = []string{
	sysreport.JobStarted,
	sysreport.JobStarted,
	sysreport.JobSuccess,
	sysreport.JobDone,
}
var statuses = []string{
	"Inqueueing",
	"Dequeueing",
	"Dequeueing",
	"Dequeueing",
}

func (a *ArmoAdapter) GetCVEExceptions(workload domain.ScanCommand, accountID string) (domain.CVEExceptions, error) {
	backendURL := "https://api.armosec.io/api"

	designator := armotypes.PortalDesignator{
		DesignatorType: armotypes.DesignatorAttribute,
		Attributes: map[string]string{
			"customerGUID":        accountID,
			"scope.cluster":       wlidpkg.GetClusterFromWlid(workload.Wlid),
			"scope.namespace":     wlidpkg.GetNamespaceFromWlid(workload.Wlid),
			"scope.kind":          strings.ToLower(wlidpkg.GetKindFromWlid(workload.Wlid)),
			"scope.name":          wlidpkg.GetNameFromWlid(workload.Wlid),
			"scope.containerName": workload.ContainerName,
		},
	}

	vulnExceptionList, err := wssc.BackendGetCVEExceptionByDEsignator(backendURL, accountID, &designator)
	if err != nil {
		return nil, err
	}
	return vulnExceptionList, nil
}

// SendStatus sends the given status and details to the platform
func (a *ArmoAdapter) SendStatus(workload domain.ScanCommand, step int) error {
	lastAction := workload.LastAction + 1
	report := sysreport.NewBaseReport(
		a.clusterConfig.AccountID,
		ReporterName,
		a.clusterConfig.EventReceiverRestURL,
		&http.Client{},
	)
	report.Status = statuses[step]
	report.Target = fmt.Sprintf("vuln scan:: scanning wlid: %v , container: %v imageTag: %v imageHash: %s",
		workload.Wlid, workload.ContainerName, workload.ImageTag, workload.ImageHash)
	report.ActionID = strconv.Itoa(lastAction)
	report.ActionIDN = lastAction
	report.ActionName = ActionName
	report.JobID = workload.JobID
	report.ParentAction = workload.ParentJobID
	report.Details = details[step]

	ReportErrorsChan := make(chan error)
	report.SendStatus(sysreport.JobSuccess, true, ReportErrorsChan)
	err := <-ReportErrorsChan
	return err
}

// SubmitCVE submits the given CVE to the platform
func (a *ArmoAdapter) SubmitCVE(cve domain.CVEManifest) error {
	//TODO implement me
	panic("implement me")
}
