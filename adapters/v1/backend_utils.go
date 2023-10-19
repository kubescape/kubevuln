package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/containerscan"
	v1 "github.com/armosec/armoapi-go/containerscan/v1"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/armosec/utils-go/httputils"
	"github.com/armosec/utils-k8s-go/armometadata"
	beClient "github.com/kubescape/backend/pkg/client/v1"
	beServer "github.com/kubescape/backend/pkg/server/v1"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubevuln/core/domain"
)

func (a *BackendAdapter) sendSummaryAndVulnerabilities(ctx context.Context, report *v1.ScanResultReport, eventReceiverURL string, totalVulnerabilities int, scanID string, firstVulnerabilitiesChunk []containerscan.CommonContainerVulnerabilityResult, errChan chan<- error, sendWG *sync.WaitGroup) (nextPartNum int) {
	//get the first chunk
	firstChunkVulnerabilitiesCount := len(firstVulnerabilitiesChunk)
	//if size of summary + first chunk does not exceed max size
	if httputils.JSONSize(report)+httputils.JSONSize(firstVulnerabilitiesChunk) <= maxBodySize {
		//then post the summary report with the first vulnerabilities chunk
		report.Vulnerabilities = firstVulnerabilitiesChunk
		//if all vulnerabilities got into the first chunk set this as the last report
		report.PaginationInfo.IsLastReport = totalVulnerabilities == firstChunkVulnerabilitiesCount
		//first chunk sent (or is nil) so set to nil
		firstVulnerabilitiesChunk = nil
	} else {
		//first chunk is not included in the summary, so if there are vulnerabilities to send set the last part to false
		report.PaginationInfo.IsLastReport = firstChunkVulnerabilitiesCount == 0
	}
	//send the summary report
	a.postResultsAsGoroutine(ctx, report, eventReceiverURL, report.Summary.ImageTag, report.Summary.WLID, errChan, sendWG)
	nextPartNum++
	//send the first chunk if it was not sent yet (because of summary size)
	if firstVulnerabilitiesChunk != nil {
		a.postResultsAsGoroutine(ctx,
			&v1.ScanResultReport{
				PaginationInfo:  apis.PaginationMarks{ReportNumber: nextPartNum, IsLastReport: totalVulnerabilities == firstChunkVulnerabilitiesCount},
				Vulnerabilities: firstVulnerabilitiesChunk,
				ContainerScanID: scanID,
				Timestamp:       report.Timestamp,
				Designators:     report.Designators,
			}, eventReceiverURL, report.Summary.ImageTag, report.Summary.WLID, errChan, sendWG)
		nextPartNum++
	}
	return nextPartNum
}

func (a *BackendAdapter) postResultsAsGoroutine(ctx context.Context, report *v1.ScanResultReport, eventReceiverURL, imagetag string, wlid string, errorChan chan<- error, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(report *v1.ScanResultReport, eventReceiverURL, imagetag string, wlid string, errorChan chan<- error, wg *sync.WaitGroup) {
		defer wg.Done()
		a.postResults(ctx, report, eventReceiverURL, imagetag, wlid, errorChan)
	}(report, eventReceiverURL, imagetag, wlid, errorChan, wg)
}

func (a *BackendAdapter) getRequestHeaders() map[string]string {
	return map[string]string{
		"Content-Type":           "application/json",
		beServer.AccessKeyHeader: a.accessKey,
	}
}

func (a *BackendAdapter) postResults(ctx context.Context, report *v1.ScanResultReport, eventReceiverURL, imagetag, wlid string, errorChan chan<- error) {
	payload, err := json.Marshal(report)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to convert to json", helpers.Error(err),
			helpers.String("wlid", wlid))
		errorChan <- err
		return
	}

	urlBase, err := beClient.GetVulnerabilitiesReportURL(eventReceiverURL, report.Designators.Attributes[identifiers.AttributeCustomerGUID])
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to get vulnerabilities report url", helpers.Error(err),
			helpers.String("wlid", wlid))
		errorChan <- err
		return
	}

	resp, err := a.httpPostFunc(http.DefaultClient, urlBase.String(), a.getRequestHeaders(), payload)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed posting to event", helpers.Error(err),
			helpers.String("image", imagetag),
			helpers.String("wlid", wlid))
		errorChan <- err
		return
	}
	defer resp.Body.Close()
	body, err := httputils.HttpRespToString(resp)
	if err != nil {
		logger.L().Ctx(ctx).Error("Vulnerabilities post to event receiver failed", helpers.Error(err),
			helpers.String("body", body))
		errorChan <- err
		return
	}
	logger.L().Debug(fmt.Sprintf("posting to event receiver image %s wlid %s finished successfully response body: %s", imagetag, wlid, body)) // systest dependent
}

func (a *BackendAdapter) sendVulnerabilitiesRoutine(ctx context.Context, chunksChan <-chan []containerscan.CommonContainerVulnerabilityResult, eventReceiverURL string, scanID string, finalReport v1.ScanResultReport, errChan chan error, sendWG *sync.WaitGroup, totalVulnerabilities int, firstChunkVulnerabilitiesCount int, nextPartNum int) {
	go func(scanID string, finalReport v1.ScanResultReport, errorChan chan<- error, sendWG *sync.WaitGroup, expectedVulnerabilitiesSum int, partNum int) {
		a.sendVulnerabilities(ctx, chunksChan, eventReceiverURL, partNum, expectedVulnerabilitiesSum, scanID, finalReport, errorChan, sendWG)
		//wait for all post request to end (including summary report)
		sendWG.Wait()
		//no more post requests - close the error channel
		close(errorChan)
	}(scanID, finalReport, errChan, sendWG, totalVulnerabilities-firstChunkVulnerabilitiesCount, nextPartNum)
}

func (a *BackendAdapter) sendVulnerabilities(ctx context.Context, chunksChan <-chan []containerscan.CommonContainerVulnerabilityResult, eventReceiverURL string, partNum int, expectedVulnerabilitiesSum int, scanID string, finalReport v1.ScanResultReport, errorChan chan<- error, sendWG *sync.WaitGroup) {
	//post each vulnerability chunk in a different report
	chunksVulnerabilitiesCount := 0
	for vulnerabilities := range chunksChan {
		chunksVulnerabilitiesCount += len(vulnerabilities)
		a.postResultsAsGoroutine(ctx,
			&v1.ScanResultReport{
				PaginationInfo:  apis.PaginationMarks{ReportNumber: partNum, IsLastReport: chunksVulnerabilitiesCount == expectedVulnerabilitiesSum},
				Vulnerabilities: vulnerabilities,
				ContainerScanID: scanID,
				Timestamp:       finalReport.Timestamp,
				Designators:     finalReport.Designators,
			}, eventReceiverURL, finalReport.Summary.ImageTag, finalReport.Summary.WLID, errorChan, sendWG)
		partNum++
	}

	//verify that all vulnerabilities received and sent
	if chunksVulnerabilitiesCount != expectedVulnerabilitiesSum {
		errorChan <- fmt.Errorf("error while splitting vulnerabilities chunks, expected " + strconv.Itoa(expectedVulnerabilitiesSum) +
			" vulnerabilities but received " + strconv.Itoa(chunksVulnerabilitiesCount))
	}
}

func incrementCounter(counter *int64, isGlobal, isIgnored bool) {
	if isGlobal && isIgnored {
		return
	}
	*counter++
}

func summarize(report v1.ScanResultReport, vulnerabilities []containerscan.CommonContainerVulnerabilityResult, workload domain.ScanCommand, hasRelevancy bool) (*containerscan.CommonContainerScanSummaryResult, []containerscan.CommonContainerVulnerabilityResult) {
	summary := containerscan.CommonContainerScanSummaryResult{
		Designators:      report.Designators,
		SeverityStats:    containerscan.SeverityStats{},
		CustomerGUID:     report.Designators.Attributes[identifiers.AttributeCustomerGUID],
		ContainerScanID:  report.ContainerScanID,
		WLID:             workload.Wlid,
		ImageID:          workload.ImageHash,
		ImageTag:         workload.ImageTagNormalized,
		ClusterName:      report.Designators.Attributes[identifiers.AttributeCluster],
		Namespace:        report.Designators.Attributes[identifiers.AttributeNamespace],
		ContainerName:    report.Designators.Attributes[identifiers.AttributeContainerName],
		JobIDs:           workload.Session.JobIDs,
		Timestamp:        report.Timestamp,
		HasRelevancyData: hasRelevancy,
	}

	imageInfo, err := armometadata.ImageTagToImageInfo(workload.ImageTagNormalized)
	if err == nil {
		summary.Registry = imageInfo.Registry
		summary.Version = imageInfo.VersionImage
	}

	summary.PackagesName = make([]string, 0)

	actualSeveritiesStats := map[string]containerscan.SeverityStats{}
	exculdedSeveritiesStats := map[string]containerscan.SeverityStats{}

	vulnsList := make([]containerscan.ShortVulnerabilityResult, 0)

	for i := range vulnerabilities {
		isIgnored := len(vulnerabilities[i].ExceptionApplied) > 0 &&
			len(vulnerabilities[i].ExceptionApplied[0].Actions) > 0 &&
			vulnerabilities[i].ExceptionApplied[0].Actions[0] == armotypes.Ignore

		severitiesStats := exculdedSeveritiesStats
		if !isIgnored {
			summary.TotalCount++
			vulnsList = append(vulnsList, *(vulnerabilities[i].ToShortVulnerabilityResult()))
			severitiesStats = actualSeveritiesStats
		}

		// TODO: maybe add all severities just to have a placeholders
		if !containerscan.KnownSeverities[vulnerabilities[i].Severity] {
			vulnerabilities[i].Severity = containerscan.UnknownSeverity
		}

		vulnSeverityStats, ok := severitiesStats[vulnerabilities[i].Severity]
		if !ok {
			vulnSeverityStats = containerscan.SeverityStats{Severity: vulnerabilities[i].Severity}
		}

		vulnSeverityStats.TotalCount++
		isFixed := containerscan.CalculateFixed(vulnerabilities[i].Fixes) > 0
		if isFixed {
			vulnSeverityStats.FixAvailableOfTotalCount++
			incrementCounter(&summary.FixAvailableOfTotalCount, true, isIgnored)
		}
		isRCE := vulnerabilities[i].IsRCE()
		if isRCE {
			vulnSeverityStats.RCECount++
			incrementCounter(&summary.RCECount, true, isIgnored)
			if isFixed {
				vulnSeverityStats.RCEFixCount++
				incrementCounter(&summary.RCEFixCount, true, isIgnored)
			}
		}

		isRelevant := vulnerabilities[i].GetIsRelevant()
		if isRelevant != nil { // if IsRelevant is not nil, we have relevancy data
			if *isRelevant {
				// vulnerability is relevant
				vulnerabilities[i].SetRelevantLabel(containerscan.RelevantLabelYes)
				vulnSeverityStats.RelevantCount++
				incrementCounter(&summary.RelevantCount, true, isIgnored)
				if isFixed {
					vulnSeverityStats.RelevantFixCount++
					incrementCounter(&summary.RelevantFixCount, true, isIgnored)
				}
			} else {
				// vulnerability is not relevant
				vulnerabilities[i].SetRelevantLabel(containerscan.RelevantLabelNo)
			}
		}
		severitiesStats[vulnerabilities[i].Severity] = vulnSeverityStats
	}

	summary.Status = "Success"
	summary.Vulnerabilities = vulnsList

	// if there is no CVEp, label is empty
	if !hasRelevancy {
		summary.SetRelevantLabel(containerscan.RelevantLabelNotExists)
	} else {
		// mark relevancy scan in severities stats
		for severity, severityStats := range actualSeveritiesStats {
			severityStats.RelevancyScanCount = 1
			actualSeveritiesStats[severity] = severityStats
		}
		summary.SeverityStats.RelevancyScanCount = 1
		if summary.SeverityStats.RelevantCount == 0 {
			// if there is CVEp but no relevant vulnerabilities, label is "no"
			summary.SetRelevantLabel(containerscan.RelevantLabelNo)
		} else {
			// if there is CVEp and there are relevant vulnerabilities, label is "yes"
			summary.SetRelevantLabel(containerscan.RelevantLabelYes)
		}
	}

	for sever := range actualSeveritiesStats {
		summary.SeveritiesStats = append(summary.SeveritiesStats, actualSeveritiesStats[sever])
	}
	for sever := range exculdedSeveritiesStats {
		summary.ExcludedSeveritiesStats = append(summary.ExcludedSeveritiesStats, exculdedSeveritiesStats[sever])
	}

	return &summary, vulnerabilities
}

func getCVEExceptionMatchCVENameFromList(srcCVEList []armotypes.VulnerabilityExceptionPolicy, CVEName string, filterFixed bool) []armotypes.VulnerabilityExceptionPolicy {
	var l []armotypes.VulnerabilityExceptionPolicy

	for i := range srcCVEList {
		for j := range srcCVEList[i].VulnerabilityPolicies {
			if srcCVEList[i].VulnerabilityPolicies[j].Name == CVEName {
				if filterFixed && srcCVEList[i].ExpiredOnFix != nil && *srcCVEList[i].ExpiredOnFix {
					continue
				}
				l = append(l, srcCVEList[i])
			}
		}
	}

	if len(l) > 0 {
		return l
	}
	return nil
}
