package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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

// sendError delivers err to errorChan. It always wins the send when the channel has room,
// even if ctx is already cancelled, so a cancelled context never causes a real error to be
// dropped in favor of a stale one already sitting in the channel. Only once the channel is
// actually saturated do we fall back to waiting for room or for ctx cancellation, logging a
// warning if we ultimately have to give up.
func sendError(ctx context.Context, errorChan chan<- error, err error) {
	if errorChan == nil || err == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case errorChan <- err:
		return
	default:
	}
	// only now consider giving up
	select {
	case errorChan <- err:
	case <-ctx.Done():
		logger.L().Ctx(ctx).Warning("dropping error, context cancelled", helpers.Error(err))
	}
}

// sendSummaryAndVulnerabilities posts the summary report synchronously so it always reaches the
// backend before any chunk report (preventing the "missing summary for containerScanID"
// rejection, #437). If the summary post fails, no chunk is dispatched here: the backend would
// reject every one of them anyway without a summary on file, so there is nothing to gain by
// sending them (#446). Callers must treat a non-nil error as "nothing was sent" and must not
// dispatch the remaining chunks either.
func (a *BackendAdapter) sendSummaryAndVulnerabilities(ctx context.Context, report *v1.ScanResultReport, eventReceiverURL string, totalVulnerabilities int, scanID string, firstVulnerabilitiesChunk []containerscan.CommonContainerVulnerabilityResult, errChan chan<- error, sendWG *sync.WaitGroup) (nextPartNum int, err error) {
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
	if err := a.postResults(ctx, *report, eventReceiverURL, report.Summary.ImageTag, report.Summary.WLID); err != nil {
		return 0, fmt.Errorf("failed to send summary report: %w", err)
	}
	nextPartNum = 1
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
	return nextPartNum, nil
}

func (a *BackendAdapter) postResultsAsGoroutine(ctx context.Context, report *v1.ScanResultReport, eventReceiverURL, imagetag, wlid string, errorChan chan<- error, wg *sync.WaitGroup) {
	wg.Add(1)
	go func(report v1.ScanResultReport, eventReceiverURL, imagetag, wlid string, errorChan chan<- error, wg *sync.WaitGroup) {
		defer wg.Done()

		// postResults returns errors to the caller. Since this function runs in a
		// goroutine and nothing is synchronously waiting on the return value, it
		// forwards any returned error to errorChan.
		if err := a.postResults(ctx, report, eventReceiverURL, imagetag, wlid); err != nil {
			sendError(ctx, errorChan, err)
		}
	}(*report, eventReceiverURL, imagetag, wlid, errorChan, wg)
}

func (a *BackendAdapter) getRequestHeaders() map[string]string {
	return map[string]string{
		"Content-Type":           "application/json",
		beServer.AccessKeyHeader: a.accessKey,
	}
}

// postResults posts a single report and returns the failure, if any.
// Callers that run it in a goroutine are responsible for forwarding the error to errorChan.
func (a *BackendAdapter) postResults(
	ctx context.Context,
	report v1.ScanResultReport,
	eventReceiverURL, imagetag, wlid string,
) error {
	payload, err := json.Marshal(report)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to convert to json", helpers.Error(err),
			helpers.String("wlid", wlid))
		return err
	}

	urlBase, err := beClient.GetVulnerabilitiesReportURL(eventReceiverURL, report.Designators.Attributes[identifiers.AttributeCustomerGUID])
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to get vulnerabilities report url", helpers.Error(err),
			helpers.String("wlid", wlid))
		return err
	}

	resp, err := a.httpPostFunc(ctx, a.getHTTPClient(), urlBase.String(), a.getRequestHeaders(), payload, 60*time.Second)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "429") || strings.Contains(errStr, "Too Many Requests") {
			logger.L().Ctx(ctx).Error("failed sending vulnerabilities report due to rate limiting (429 Too Many Requests). Please ask your vendor for support",
				helpers.Error(err),
				helpers.String("image", imagetag),
				helpers.String("wlid", wlid))
		} else {
			logger.L().Ctx(ctx).Error("failed posting to event", helpers.Error(err),
				helpers.String("image", imagetag),
				helpers.String("wlid", wlid))
		}
		return err
	}
	defer resp.Body.Close()
	body, err := httputils.HttpRespToString(resp)
	if err != nil {
		logger.L().Ctx(ctx).Error("failed reading response body from event receiver", helpers.Error(err),
			helpers.String("image", imagetag),
			helpers.String("wlid", wlid))
		return err
	}
	logger.L().Debug(fmt.Sprintf("posting to event receiver image %s wlid %s finished successfully response body: %s", imagetag, wlid, body)) // systest dependent
	return nil
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
		sendError(ctx, errorChan, fmt.Errorf("error while splitting vulnerabilities chunks, expected %s vulnerabilities but received %d",
			strconv.Itoa(expectedVulnerabilitiesSum), chunksVulnerabilitiesCount))
	}
}

func incrementCounter(counter *int64, isIgnored bool) {
	if isIgnored {
		return
	}

	*counter++
}

func Summarize(report v1.ScanResultReport, vulnerabilities []containerscan.CommonContainerVulnerabilityResult, workload domain.ScanCommand, hasRelevancy bool, imageManifest *containerscan.ImageManifest) (*containerscan.CommonContainerScanSummaryResult, []containerscan.CommonContainerVulnerabilityResult) {
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
		ApiVersion:       report.Designators.Attributes[identifiers.AttributeApiVersion],
		ContainerName:    report.Designators.Attributes[identifiers.AttributeContainerName],
		JobIDs:           workload.Session.JobIDs,
		Timestamp:        report.Timestamp,
		HasRelevancyData: hasRelevancy,
		ImageManifest:    imageManifest,
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
		// Same predicate ApplySecurityExceptions uses to decide suppression for the stored
		// manifest. Reading only ExceptionApplied[0].Actions[0] would answer a narrower
		// question: getCVEExceptionMatchCVENameFromList appends every policy matching the
		// CVE name without filtering on actions, so the first one is not necessarily the
		// one carrying Ignore, and the two surfaces would then disagree about whether the
		// finding is suppressed.
		isIgnored := hasIgnoreAction(vulnerabilities[i].ExceptionApplied)

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
			incrementCounter(&summary.FixAvailableOfTotalCount, isIgnored)
		}
		isRCE := vulnerabilities[i].IsRCE()
		if isRCE {
			vulnSeverityStats.RCECount++
			incrementCounter(&summary.RCECount, isIgnored)
			if isFixed {
				vulnSeverityStats.RCEFixCount++
				incrementCounter(&summary.RCEFixCount, isIgnored)
			}
		}

		isRelevant := vulnerabilities[i].GetIsRelevant()
		if isRelevant != nil { // if IsRelevant is not nil, we have relevancy data
			if *isRelevant {
				// vulnerability is relevant
				vulnerabilities[i].SetRelevantLabel(containerscan.RelevantLabelYes)
				vulnSeverityStats.RelevantCount++
				incrementCounter(&summary.RelevantCount, isIgnored)
				if isFixed {
					vulnSeverityStats.RelevantFixCount++
					incrementCounter(&summary.RelevantFixCount, isIgnored)
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
	// Both were collected in a map, whose iteration order Go randomises, so without this the
	// same findings produce a differently ordered summary on every scan. That summary is the
	// payload posted to the backend, so a consumer diffing two reports for the same image
	// sees the severity stats move around when nothing about the image changed.
	sortBySeverity(summary.SeveritiesStats)
	sortBySeverity(summary.ExcludedSeveritiesStats)

	return &summary, vulnerabilities
}

// sortBySeverity orders severity stats by severity name, so a summary built from the same
// findings is byte for byte the same each time.
func sortBySeverity(stats []containerscan.SeverityStats) {
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Severity < stats[j].Severity
	})
}

func getCVEExceptionMatchCVENameFromList(srcCVEList []armotypes.VulnerabilityExceptionPolicy, CVEName string, filterFixed bool) []armotypes.VulnerabilityExceptionPolicy {
	var l []armotypes.VulnerabilityExceptionPolicy

	for i := range srcCVEList {
		if filterFixed && srcCVEList[i].ExpiredOnFix != nil && *srcCVEList[i].ExpiredOnFix {
			continue
		}
		for j := range srcCVEList[i].VulnerabilityPolicies {
			if strings.EqualFold(srcCVEList[i].VulnerabilityPolicies[j].Name, CVEName) {
				// A policy contributes at most once. buildPolicy expands a vulnerability
				// entry into one VulnerabilityPolicy per id and alias, so an exception
				// listing an alias equal to its id, or the same alias twice, would
				// otherwise return the same policy several times, and every consumer
				// counts it that many times.
				l = append(l, srcCVEList[i])
				break
			}
		}
	}

	if len(l) > 0 {
		return l
	}
	return nil
}

// cveExceptionIndex maps a lower-cased CVE/alias name to the indices, into the exception
// list it was built from, of every exception that declares a VulnerabilityPolicy with that
// name. It lets a scan with many matches look up candidate exceptions in roughly constant
// time per match instead of re-walking every exception (and every policy within it) for
// each one, which is what getCVEExceptionMatchCVENameFromList does on its own.
type cveExceptionIndex struct {
	srcCVEList []armotypes.VulnerabilityExceptionPolicy
	byName     map[string][]int
}

// buildCVEExceptionIndex builds a cveExceptionIndex over srcCVEList in a single pass. Build
// it once per scan (the exception list does not change across matches within a scan) and
// reuse it via lookup for every match.
func buildCVEExceptionIndex(srcCVEList []armotypes.VulnerabilityExceptionPolicy) *cveExceptionIndex {
	idx := &cveExceptionIndex{
		srcCVEList: srcCVEList,
		byName:     make(map[string][]int, len(srcCVEList)),
	}
	for i := range srcCVEList {
		seen := make(map[string]struct{})
		for j := range srcCVEList[i].VulnerabilityPolicies {
			name := strings.ToLower(srcCVEList[i].VulnerabilityPolicies[j].Name)
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			idx.byName[name] = append(idx.byName[name], i)
		}
	}
	return idx
}

// lookup returns the same result getCVEExceptionMatchCVENameFromList(idx.srcCVEList, CVEName,
// filterFixed) would return, but only inspects the exceptions that actually declare a policy
// named CVEName rather than the full exception list.
func (idx *cveExceptionIndex) lookup(CVEName string, filterFixed bool) []armotypes.VulnerabilityExceptionPolicy {
	if idx == nil {
		return nil
	}
	indices := idx.byName[strings.ToLower(CVEName)]
	if len(indices) == 0 {
		return nil
	}

	var l []armotypes.VulnerabilityExceptionPolicy
	for _, i := range indices {
		exc := idx.srcCVEList[i]
		if filterFixed && exc.ExpiredOnFix != nil && *exc.ExpiredOnFix {
			continue
		}
		l = append(l, exc)
	}

	if len(l) > 0 {
		return l
	}
	return nil
}
