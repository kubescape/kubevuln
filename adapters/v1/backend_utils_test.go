package v1

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/apis"
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/containerscan"
	v1 "github.com/armosec/armoapi-go/containerscan/v1"
	"github.com/armosec/armoapi-go/identifiers"
	"github.com/armosec/utils-go/httputils"
	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/pointer"
)

func TestGetCVEExceptionMatchCVENameFromList(t *testing.T) {
	testCases := []struct {
		name       string
		srcCVEList []armotypes.VulnerabilityExceptionPolicy
		CVEName    string
		expected   []armotypes.VulnerabilityExceptionPolicy
		isFixed    bool
	}{
		{
			name:       "empty source list",
			srcCVEList: []armotypes.VulnerabilityExceptionPolicy{},
			CVEName:    "CVE-2021-1234",
			expected:   nil,
		},
		{
			name: "no matches in source list",
			srcCVEList: []armotypes.VulnerabilityExceptionPolicy{
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2022-5678"},
					},
				},
			},
			CVEName:  "CVE-2021-1234",
			expected: nil,
		},
		{
			name: "one match in source list",
			srcCVEList: []armotypes.VulnerabilityExceptionPolicy{
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-1234"},
					},
				},
			},
			CVEName: "CVE-2021-1234",
			expected: []armotypes.VulnerabilityExceptionPolicy{
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-1234"},
					},
				},
			},
		},
		{
			name: "multiple matches in source list",
			srcCVEList: []armotypes.VulnerabilityExceptionPolicy{
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-1234"},
					},
				},
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-5678"},
						{Name: "CVE-2021-1234"},
					},
				},
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-1234"},
						{Name: "CVE-2021-9012"},
					},
				},
			},
			CVEName: "CVE-2021-1234",
			isFixed: true,
			expected: []armotypes.VulnerabilityExceptionPolicy{
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-1234"},
					},
				},
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-5678"},
						{Name: "CVE-2021-1234"},
					},
				},
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-1234"},
						{Name: "CVE-2021-9012"},
					},
				},
			},
		},
		{
			name:    "multiple matches in source list filtered by with expiration on fix",
			isFixed: true,
			srcCVEList: []armotypes.VulnerabilityExceptionPolicy{
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-1234"},
					},
					ExpiredOnFix: pointer.Bool(true),
				},
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-5678"},
						{Name: "CVE-2021-1234"},
					},
				},
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-1234"},
						{Name: "CVE-2021-9012"},
					},
					ExpiredOnFix: pointer.Bool(true),
				},
			},
			CVEName: "CVE-2021-1234",
			expected: []armotypes.VulnerabilityExceptionPolicy{
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-5678"},
						{Name: "CVE-2021-1234"},
					},
				},
			},
		},
		{
			name:    "one match in source list, filter fix with no expire on fix",
			isFixed: true,
			srcCVEList: []armotypes.VulnerabilityExceptionPolicy{
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-1234"},
					},
				},
			},
			CVEName: "CVE-2021-1234",
			expected: []armotypes.VulnerabilityExceptionPolicy{
				{
					VulnerabilityPolicies: []armotypes.VulnerabilityPolicy{
						{Name: "CVE-2021-1234"},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := getCVEExceptionMatchCVENameFromList(tc.srcCVEList, tc.CVEName, tc.isFixed)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

//go:embed testdata/nginx-image-manifest.json
var nginxImageManifest []byte

func Test_summarize(t *testing.T) {
	var imageManifest containerscan.ImageManifest
	assert.NoError(t, json.Unmarshal(nginxImageManifest, &imageManifest))
	containerScanID := "9711c327-1a08-487e-b24a-72128712ef2d"
	designators := identifiers.PortalDesignator{
		DesignatorType: "Attributes",
		Attributes: map[string]string{
			"cluster":       "minikube",
			"namespace":     "default",
			"kind":          "deployment",
			"name":          "nginx",
			"containerName": "nginx",
			"workloadHash":  "8449841542515860619",
			"customerGUID":  "3fcd1e54-7871-49dc-8ebf-8d828d28c00b",
		},
	}
	imageHash := "imagehash"
	imageTag := "imagetag"
	jobIDs := []string{
		"80fc5ba7-e6df-4d8f-ae94-475242cd7345",
		"b56211c7-716a-4f9f-b27f-b4942195fa5e",
	}
	timestamp := time.Now().Unix()
	wlid := "wlid"
	type args struct {
		report          v1.ScanResultReport
		vulnerabilities []containerscan.CommonContainerVulnerabilityResult
		workload        domain.ScanCommand
		hasRelevancy    bool
		imageManifest   *containerscan.ImageManifest
	}
	tests := []struct {
		name string
		args args
		want *containerscan.CommonContainerScanSummaryResult
	}{
		{
			name: "empty args",
			args: args{
				report:       v1.ScanResultReport{},
				workload:     domain.ScanCommand{},
				hasRelevancy: false,
			},
			want: &containerscan.CommonContainerScanSummaryResult{
				PackagesName:    []string{},
				Status:          "Success",
				Vulnerabilities: []containerscan.ShortVulnerabilityResult{},
			},
		},
		{
			name: "empty report",
			args: args{
				report: v1.ScanResultReport{},
				workload: domain.ScanCommand{
					ImageHash:          imageHash,
					Wlid:               wlid,
					ImageTag:           imageTag,
					ImageTagNormalized: imageTag,
					Session: domain.Session{
						JobIDs: jobIDs,
					},
				},
				hasRelevancy: false,
			},
			want: &containerscan.CommonContainerScanSummaryResult{
				ImageID:         imageHash,
				ImageTag:        imageTag,
				JobIDs:          jobIDs,
				PackagesName:    []string{},
				Status:          "Success",
				Version:         imageTag,
				Vulnerabilities: []containerscan.ShortVulnerabilityResult{},
				WLID:            wlid,
			},
		},
		{
			name: "real report",
			args: args{
				report: v1.ScanResultReport{
					ContainerScanID: containerScanID,
					Designators:     designators,
					Timestamp:       timestamp,
				},
				vulnerabilities: []containerscan.CommonContainerVulnerabilityResult{
					{
						ContainerScanID:   containerScanID,
						Designators:       designators,
						IntroducedInLayer: dummyLayer,
						IsFixed:           0,
						IsLastScan:        1,
						Layers:            []containerscan.ESLayer{{LayerHash: dummyLayer}},
						Vulnerability: containerscan.Vulnerability{
							IsRelevant: nil,
							ImageID:    imageHash,
							ImageTag:   imageTag,
							Severity:   "Negligible",
							Name:       "CVE-2005-2541",
							Categories: containerscan.VulnerabilityCategory{IsRCE: false},
						},
						WLID: wlid,
					},
					{
						ContainerScanID:   containerScanID,
						Designators:       designators,
						IntroducedInLayer: dummyLayer,
						IsFixed:           1,
						IsLastScan:        1,
						Layers:            []containerscan.ESLayer{{LayerHash: dummyLayer}},
						Vulnerability: containerscan.Vulnerability{
							IsRelevant: nil,
							ImageID:    imageHash,
							ImageTag:   imageTag,
							Severity:   "Medium",
							Name:       "CVE-2016-9318",
							Fixes:      containerscan.VulFixes{{Version: "foo"}},
							Categories: containerscan.VulnerabilityCategory{IsRCE: false},
						},
						WLID: wlid,
					},
					{
						ContainerScanID:   containerScanID,
						Designators:       designators,
						IntroducedInLayer: dummyLayer,
						IsFixed:           1,
						IsLastScan:        1,
						Layers:            []containerscan.ESLayer{{LayerHash: dummyLayer}},
						Vulnerability: containerscan.Vulnerability{
							IsRelevant:  nil,
							ImageID:     imageHash,
							ImageTag:    imageTag,
							Description: "code execution",
							Severity:    "Critical",
							Name:        "CVE-2017-18269",
							Fixes:       containerscan.VulFixes{{Version: "foo"}},
							Categories:  containerscan.VulnerabilityCategory{IsRCE: true},
						},
						WLID: wlid,
					},
					{
						ContainerScanID:   containerScanID,
						Designators:       designators,
						IntroducedInLayer: dummyLayer,
						IsFixed:           1,
						IsLastScan:        1,
						Layers:            []containerscan.ESLayer{{LayerHash: dummyLayer}},
						Vulnerability: containerscan.Vulnerability{
							IsRelevant:  nil,
							ImageID:     imageHash,
							ImageTag:    imageTag,
							Description: "command injection",
							Severity:    "Critical",
							Name:        "CVE-2022-1292",
							Fixes:       containerscan.VulFixes{{Version: "foo"}},
							Categories:  containerscan.VulnerabilityCategory{IsRCE: true},
						},
						WLID: wlid,
					},
				},
				workload: domain.ScanCommand{
					ImageHash:          imageHash,
					Wlid:               wlid,
					ImageTag:           imageTag,
					ImageTagNormalized: imageTag,
					Session: domain.Session{
						JobIDs: jobIDs,
					},
				},
				hasRelevancy:  false,
				imageManifest: &imageManifest,
			},
			want: &containerscan.CommonContainerScanSummaryResult{
				ClusterName:     designators.Attributes["cluster"],
				ContainerName:   designators.Attributes["containerName"],
				ContainerScanID: containerScanID,
				CustomerGUID:    designators.Attributes["customerGUID"],
				Designators:     designators,
				ImageID:         imageHash,
				ImageTag:        imageTag,
				JobIDs:          jobIDs,
				Namespace:       designators.Attributes["namespace"],
				PackagesName:    []string{},
				SeveritiesStats: []containerscan.SeverityStats{
					{Severity: "Critical", TotalCount: 2, RCEFixCount: 2, FixAvailableOfTotalCount: 2, RCECount: 2, RelevancyScanCount: 0},
					{Severity: "Medium", TotalCount: 1, FixAvailableOfTotalCount: 1, RelevancyScanCount: 0},
					{Severity: "Negligible", TotalCount: 1, RelevancyScanCount: 0},
				},
				SeverityStats: containerscan.SeverityStats{
					TotalCount:               4,
					RCEFixCount:              2,
					FixAvailableOfTotalCount: 3,
					RCECount:                 2,
					RelevancyScanCount:       0,
				},
				Status:    "Success",
				Timestamp: timestamp,
				Version:   imageTag,
				Vulnerabilities: []containerscan.ShortVulnerabilityResult{
					{Name: "CVE-2005-2541"},
					{Name: "CVE-2016-9318"},
					{Name: "CVE-2017-18269"},
					{Name: "CVE-2022-1292"},
				},
				WLID:          wlid,
				ImageManifest: &imageManifest,
			},
		},
		{
			name: "real report with relevancy",
			args: args{
				report: v1.ScanResultReport{
					ContainerScanID: containerScanID,
					Designators:     designators,
					Timestamp:       timestamp,
				},
				vulnerabilities: []containerscan.CommonContainerVulnerabilityResult{
					{
						ContainerScanID:   containerScanID,
						Designators:       designators,
						IntroducedInLayer: dummyLayer,
						IsFixed:           0,
						IsLastScan:        1,
						Layers:            []containerscan.ESLayer{{LayerHash: dummyLayer}},
						Vulnerability: containerscan.Vulnerability{
							IsRelevant: pointer.Bool(false),
							ImageID:    imageHash,
							ImageTag:   imageTag,
							Severity:   "Negligible",
							Name:       "CVE-2005-2541",
							Categories: containerscan.VulnerabilityCategory{IsRCE: false},
						},
						WLID: wlid,
					},
					{
						ContainerScanID:   containerScanID,
						Designators:       designators,
						IntroducedInLayer: dummyLayer,
						IsFixed:           1,
						IsLastScan:        1,
						Layers:            []containerscan.ESLayer{{LayerHash: dummyLayer}},
						Vulnerability: containerscan.Vulnerability{
							IsRelevant: pointer.Bool(false),
							ImageID:    imageHash,
							ImageTag:   imageTag,
							Severity:   "Medium",
							Name:       "CVE-2016-9318",
							Fixes:      containerscan.VulFixes{{Version: "foo"}},
							Categories: containerscan.VulnerabilityCategory{IsRCE: false},
						},
						WLID: wlid,
					},
					{
						ContainerScanID:   containerScanID,
						Designators:       designators,
						IntroducedInLayer: dummyLayer,
						IsFixed:           1,
						IsLastScan:        1,
						Layers:            []containerscan.ESLayer{{LayerHash: dummyLayer}},
						Vulnerability: containerscan.Vulnerability{
							IsRelevant:  pointer.Bool(false),
							ImageID:     imageHash,
							ImageTag:    imageTag,
							Description: "code execution",
							Severity:    "Critical",
							Name:        "CVE-2017-18269",
							Fixes:       containerscan.VulFixes{{Version: "foo"}},
							Categories:  containerscan.VulnerabilityCategory{IsRCE: true},
						},
						WLID: wlid,
					},
					{
						ContainerScanID:   containerScanID,
						Designators:       designators,
						IntroducedInLayer: dummyLayer,
						IsFixed:           1,
						IsLastScan:        1,
						Layers:            []containerscan.ESLayer{{LayerHash: dummyLayer}},
						Vulnerability: containerscan.Vulnerability{
							IsRelevant:  pointer.Bool(true),
							ImageID:     imageHash,
							ImageTag:    imageTag,
							Description: "command injection",
							Severity:    "Critical",
							Name:        "CVE-2022-1292",
							Fixes:       containerscan.VulFixes{{Version: "foo"}},
							Categories:  containerscan.VulnerabilityCategory{IsRCE: true},
						},
						WLID: wlid,
					},
				},
				workload: domain.ScanCommand{
					ImageHash:          imageHash,
					Wlid:               wlid,
					ImageTag:           imageTag,
					ImageTagNormalized: imageTag,
					Session: domain.Session{
						JobIDs: jobIDs,
					},
				},
				hasRelevancy:  true,
				imageManifest: &imageManifest,
			},
			want: &containerscan.CommonContainerScanSummaryResult{
				ClusterName:      designators.Attributes["cluster"],
				ContainerName:    designators.Attributes["containerName"],
				ContainerScanID:  containerScanID,
				CustomerGUID:     designators.Attributes["customerGUID"],
				Designators:      designators,
				HasRelevancyData: true,
				ImageID:          imageHash,
				ImageTag:         imageTag,
				JobIDs:           jobIDs,
				Namespace:        designators.Attributes["namespace"],
				PackagesName:     []string{},
				RelevantLabel:    "yes",
				SeveritiesStats: []containerscan.SeverityStats{
					{Severity: "Critical", TotalCount: 2, RCEFixCount: 2, FixAvailableOfTotalCount: 2, RCECount: 2, RelevantCount: 1, RelevantFixCount: 1, RelevancyScanCount: 1},
					{Severity: "Medium", TotalCount: 1, FixAvailableOfTotalCount: 1, RelevancyScanCount: 1},
					{Severity: "Negligible", TotalCount: 1, RelevancyScanCount: 1},
				},
				SeverityStats: containerscan.SeverityStats{
					TotalCount:               4,
					RCEFixCount:              2,
					FixAvailableOfTotalCount: 3,
					RCECount:                 2,
					RelevantCount:            1,
					RelevantFixCount:         1,
					RelevancyScanCount:       1,
				},
				Status:    "Success",
				Timestamp: timestamp,
				Version:   imageTag,
				Vulnerabilities: []containerscan.ShortVulnerabilityResult{
					{Name: "CVE-2005-2541"},
					{Name: "CVE-2016-9318"},
					{Name: "CVE-2017-18269"},
					{Name: "CVE-2022-1292"},
				},
				WLID:          wlid,
				ImageManifest: &imageManifest,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := summarize(tt.args.report, tt.args.vulnerabilities, tt.args.workload, tt.args.hasRelevancy, tt.args.imageManifest)
			sort.Slice(got.SeveritiesStats, func(i, j int) bool {
				return got.SeveritiesStats[i].Severity < got.SeveritiesStats[j].Severity
			})
			assert.Equal(t, tt.want, got)
		})
	}
}

func fileToReport(path string) *v1.ScanResultReport {
	var report *v1.ScanResultReport
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(b, &report)
	if err != nil {
		panic(err)
	}
	return report
}

func Test_sendSummaryAndVulnerabilities(t *testing.T) {
	ctx := context.Background()
	report := fileToReport("testdata/report.json")
	errChan := make(chan error)
	testCases := []struct {
		name                      string
		firstVulnerabilitiesChunk []containerscan.CommonContainerVulnerabilityResult
		expectedPaginationMarks   []apis.PaginationMarks
		totalVulnerabilities      int
		expectedNextPartNum       int
	}{
		{
			name:                      "No vulnerabilities in first chunk",
			firstVulnerabilitiesChunk: []containerscan.CommonContainerVulnerabilityResult{},
			totalVulnerabilities:      0,
			expectedNextPartNum:       1,
			expectedPaginationMarks: []apis.PaginationMarks{
				{
					ReportNumber: 0,
					IsLastReport: true,
				},
			},
		},
		{
			name:                      "Vulnerabilities in first chunk, total size does not exceed maxBodySize",
			firstVulnerabilitiesChunk: report.Vulnerabilities[:2],
			expectedNextPartNum:       1,
			totalVulnerabilities:      2,
			expectedPaginationMarks: []apis.PaginationMarks{
				{
					ReportNumber: 0,
					IsLastReport: true,
				},
			},
		},
		{
			name:                      "Vulnerabilities in first chunk, total size does not exceed maxBodySize, but not all vulnerabilities are sent in first chunk",
			firstVulnerabilitiesChunk: report.Vulnerabilities[:2],
			expectedNextPartNum:       1,
			totalVulnerabilities:      len(report.Vulnerabilities),
			expectedPaginationMarks: []apis.PaginationMarks{
				{
					ReportNumber: 0,
					IsLastReport: false,
				},
			},
		},
		{
			name:                      "Vulnerabilities in first chunk, total size exceeds maxBodySize",
			firstVulnerabilitiesChunk: report.Vulnerabilities,
			totalVulnerabilities:      len(report.Vulnerabilities),
			expectedNextPartNum:       2,
			expectedPaginationMarks: []apis.PaginationMarks{
				{
					ReportNumber: 0,
					IsLastReport: false,
				},
				{
					ReportNumber: 1,
					IsLastReport: true,
				},
			},
		},
		{
			name:                      "Vulnerabilities in first chunk, total size exceeds maxBodySize, but not all vulnerabilities are sent in first chunk",
			firstVulnerabilitiesChunk: report.Vulnerabilities,
			totalVulnerabilities:      len(report.Vulnerabilities) + 1,
			expectedNextPartNum:       2,
			expectedPaginationMarks: []apis.PaginationMarks{
				{
					ReportNumber: 0,
					IsLastReport: false,
				},
				{
					ReportNumber: 1,
					IsLastReport: false,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sendWG := &sync.WaitGroup{}
			sendWG.Add(len(tc.expectedPaginationMarks))
			var reports []v1.ScanResultReport
			mu := &sync.Mutex{}
			httpPostFunc := func(httpClient httputils.IHttpClient, fullURL string, headers map[string]string, body []byte, timeOut time.Duration) (*http.Response, error) {
				mu.Lock()
				var report v1.ScanResultReport
				err := json.Unmarshal(body, &report)
				if err != nil {
					t.Errorf("failed to unmarshal report: %v", err)
				}
				reportNumber := report.PaginationInfo.ReportNumber

				if reportNumber >= len(tc.expectedPaginationMarks) {
					t.Errorf("unexpected number of reports sent: %d", reportNumber)
				}
				reports = append(reports, report)

				assert.Equal(t, tc.expectedPaginationMarks[reportNumber].ReportNumber, reportNumber)
				assert.Equal(t, tc.expectedPaginationMarks[reportNumber].IsLastReport, report.PaginationInfo.IsLastReport)

				sendWG.Done()
				mu.Unlock()

				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewBuffer([]byte{})),
				}, nil
			}
			a := &BackendAdapter{
				clusterConfig: armometadata.ClusterConfig{},
				httpPostFunc:  httpPostFunc,
			}
			report.Vulnerabilities = []containerscan.CommonContainerVulnerabilityResult{}
			actualNextPartNum := a.sendSummaryAndVulnerabilities(ctx, report, "", tc.totalVulnerabilities, "1234", tc.firstVulnerabilitiesChunk, errChan, sendWG)
			sendWG.Wait()
			assert.Equal(t, tc.expectedNextPartNum, actualNextPartNum)
			assert.Equal(t, len(tc.expectedPaginationMarks), len(reports))
		})
	}
}
