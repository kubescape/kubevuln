package v1

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	wssc "github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	cs "github.com/armosec/cluster-container-scanner-api/containerscan"
	v1 "github.com/armosec/cluster-container-scanner-api/containerscan/v1"
	sysreport "github.com/armosec/logger-go/system-reports/datastructures"
	"github.com/armosec/utils-go/httputils"
	pkgcautils "github.com/armosec/utils-k8s-go/armometadata"
	wlidpkg "github.com/armosec/utils-k8s-go/wlid"
	"github.com/hashicorp/go-multierror"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"go.opentelemetry.io/otel"
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
const maxBodySize int = 30000

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

func (a *ArmoAdapter) GetCVEExceptions(ctx context.Context) (domain.CVEExceptions, error) {
	ctx, span := otel.Tracer("").Start(ctx, "ArmoAdapter.GetCVEExceptions")
	defer span.End()

	backendURL := "https://api.armosec.io/api" // TODO: move to config

	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey).(domain.ScanCommand)
	if !ok {
		return nil, errors.New("no workload found in context")
	}

	designator := armotypes.PortalDesignator{
		DesignatorType: armotypes.DesignatorAttribute,
		Attributes: map[string]string{
			"customerGUID":        a.clusterConfig.AccountID,
			"scope.cluster":       wlidpkg.GetClusterFromWlid(workload.Wlid),
			"scope.namespace":     wlidpkg.GetNamespaceFromWlid(workload.Wlid),
			"scope.kind":          strings.ToLower(wlidpkg.GetKindFromWlid(workload.Wlid)),
			"scope.name":          wlidpkg.GetNameFromWlid(workload.Wlid),
			"scope.containerName": workload.ContainerName,
		},
	}

	vulnExceptionList, err := wssc.BackendGetCVEExceptionByDEsignator(backendURL, a.clusterConfig.AccountID, &designator)
	if err != nil {
		return nil, err
	}
	return vulnExceptionList, nil
}

// SendStatus sends the given status and details to the platform
func (a *ArmoAdapter) SendStatus(ctx context.Context, step int) error {
	ctx, span := otel.Tracer("").Start(ctx, "ArmoAdapter.SendStatus")
	defer span.End()
	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey).(domain.ScanCommand)
	if !ok {
		return errors.New("no workload found in context")
	}

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
func (a *ArmoAdapter) SubmitCVE(ctx context.Context, cve domain.CVEManifest, hasRelevancy bool) error {
	ctx, span := otel.Tracer("").Start(ctx, "ArmoAdapter.SubmitCVE")
	defer span.End()
	// retrieve timestamp from context
	timestamp, ok := ctx.Value(domain.TimestampKey).(int64)
	if !ok {
		return errors.New("no timestamp found in context")
	}
	// retrieve scanID from context
	scanID, ok := ctx.Value(domain.ScanIDKey).(string)
	if !ok {
		return errors.New("no scanID found in context")
	}
	// retrieve workload from context
	workload, ok := ctx.Value(domain.WorkloadKey).(domain.ScanCommand)
	if !ok {
		return errors.New("no workload found in context")
	}

	finalReport := v1.ScanResultReport{
		Designators:     *armotypes.AttributesDesignatorsFromWLID(workload.Wlid),
		Summary:         nil,
		ContainerScanID: scanID,
		Vulnerabilities: cve.Content,
		Timestamp:       timestamp,
	}

	// fill designators
	finalReport.Designators.Attributes[armotypes.AttributeContainerName] = workload.ContainerName
	finalReport.Designators.Attributes[armotypes.AttributeWorkloadHash] = cs.GenerateWorkloadHash(finalReport.Designators.Attributes)
	finalReport.Designators.Attributes[armotypes.AttributeCustomerGUID] = a.clusterConfig.AccountID
	if val, ok := workload.Args[armotypes.AttributeRegistryName]; ok {
		finalReport.Designators.Attributes[armotypes.AttributeRegistryName] = val.(string)
	}
	if val, ok := workload.Args[armotypes.AttributeRepository]; ok {
		finalReport.Designators.Attributes[armotypes.AttributeRepository] = val.(string)
	}
	if val, ok := workload.Args[armotypes.AttributeTag]; ok {
		finalReport.Designators.Attributes[armotypes.AttributeTag] = val.(string)
	}
	if val, ok := workload.Args[armotypes.AttributeSensor]; ok {
		finalReport.Designators.Attributes[armotypes.AttributeSensor] = val.(string)
	}

	// fill context and designators into vulnerabilities
	armoContext := armotypes.DesignatorToArmoContext(&finalReport.Designators, "designators")
	for i := range finalReport.Vulnerabilities {
		finalReport.Vulnerabilities[i].Context = armoContext
		finalReport.Vulnerabilities[i].Designators = finalReport.Designators
	}

	// add summary
	finalReport.Summary = summarize(finalReport, workload, hasRelevancy)
	finalReport.Summary.Context = armoContext

	// split vulnerabilities to chunks
	chunksChan, totalVulnerabilities := httputils.SplitSlice2Chunks(cve.Content, maxBodySize, 10)

	// send report(s)
	sendWG := &sync.WaitGroup{}
	errChan := make(chan error, 10)
	// get the first chunk
	firstVulnerabilitiesChunk := <-chunksChan
	firstChunkVulnerabilitiesCount := len(firstVulnerabilitiesChunk)
	// send the summary and the first chunk in one or two reports according to the size
	nextPartNum := sendSummaryAndVulnerabilities(&finalReport, a.clusterConfig.EventReceiverRestURL, totalVulnerabilities, scanID, firstVulnerabilitiesChunk, errChan, sendWG)
	firstVulnerabilitiesChunk = nil
	// if not all vulnerabilities got into the first chunk
	if totalVulnerabilities != firstChunkVulnerabilitiesCount {
		//send the rest of the vulnerabilities - error channel will be closed when all vulnerabilities are sent
		sendVulnerabilitiesRoutine(chunksChan, a.clusterConfig.EventReceiverRestURL, scanID, finalReport, errChan, sendWG, totalVulnerabilities, firstChunkVulnerabilitiesCount, nextPartNum)
	} else {
		//only one chunk will be sent so need to close the error channel when it is done
		go func(wg *sync.WaitGroup, errorChan chan error) {
			//wait for summary post request to end
			wg.Wait()
			//close the error channel
			close(errorChan)
		}(sendWG, errChan)
	}

	// collect post report errors if occurred
	var err error
	for e := range errChan {
		err = multierror.Append(err, e)
	}
	return err
}
