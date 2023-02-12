package v1

import (
	"fmt"
	"net/http"
	"strconv"

	sysreport "github.com/armosec/logger-go/system-reports/datastructures"
	pkgcautils "github.com/armosec/utils-k8s-go/armometadata"
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
