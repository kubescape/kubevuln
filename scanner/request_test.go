package scanner

import (
	_ "embed"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	pkgcautils "github.com/armosec/utils-k8s-go/armometadata"

	wssc "github.com/armosec/armoapi-go/apis"
	cs "github.com/armosec/cluster-container-scanner-api/containerscan"
	armoUtils "github.com/armosec/utils-go/httputils"
	gcmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
)

//go:embed testdata/testCaseScanReport.json
var testCaseScanReportBytes []byte

//go:embed testdata/expectedScanReport.json
var expectedScanReportBytes []byte

func TestPostScanResultsToEventReceiver(t *testing.T) {
	//load scan report test case
	scanReport := cs.ScanResultReport{}
	if err := json.Unmarshal(testCaseScanReportBytes, &scanReport); err != nil {
		t.Error("Could not read testCaseVulnerabilities.json", err)
	}
	//load expected result
	expectedScanReport := cs.ScanResultReportV1{}
	if err := json.Unmarshal(expectedScanReportBytes, &expectedScanReport); err != nil {
		t.Error("Could not read expectedScanReport.json", err)
	}
	config := pkgcautils.ClusterConfig{
		ClusterName:          "test",
		AccountID:            "aaaaaaaa-1111-bbbb-2222-cccccccccccc",
		EventReceiverRestURL: "http://localhost:9111",
	}
	//setup dummy event receiver server to catch post reports requests
	var accumulatedReport *cs.ScanResultReportV1
	var reportsPartsSum, reportPartsReceived = -1, -1
	mutex := sync.Mutex{}
	testServer, err := startTestClientServer("127.0.0.1:9111", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		assert.Equal(t, r.URL.Path, "/k8s/v2/containerScan", "request path must be /k8s/containerScanV1")
		report := cs.ScanResultReportV1{}
		bodybyte, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Error("cannot read request body", err)
			return
		}
		if err := json.Unmarshal(bodybyte, &report); err != nil {
			t.Error("cannot unmarshal request body", err)
			return
		}
		reportPartsReceived++
		if report.PaginationInfo.IsLastReport {
			reportsPartsSum = report.PaginationInfo.ReportNumber
		}
		if accumulatedReport == nil {
			accumulatedReport = &report
		} else {
			accumulatedReport.Vulnerabilities = append(accumulatedReport.Vulnerabilities, report.Vulnerabilities...)
			if report.Summary != nil {
				assert.Nil(t, accumulatedReport.Summary, "got more than one summary")
				accumulatedReport.Summary = report.Summary
			}
		}
		w.WriteHeader(http.StatusOK)
	}))

	if err != nil {
		t.Error("cannot client test server", err)
		return
	}
	defer testServer.Close()

	//call postScanResultsToEventReceiver
	dummyScanCmd := &wssc.WebsocketScanCommand{}
	//postScanResultsToEventReciever blocks until all report chunks are sent to the event receiver
	dummyLayers := make(map[string]cs.ESLayer)
	err = postScanResultsToEventReceiver(&config, dummyScanCmd, scanReport.ImgTag, scanReport.ImgHash, scanReport.WLID, scanReport.ContainerName, &scanReport.Layers, dummyLayers)
	assert.NoError(t, err, "postScanResultsToEventReceiver returned an error")
	assert.Equal(t, reportsPartsSum, reportPartsReceived, "reportPartsReceived must be equal to reportsPartsSum")
	assert.NotNil(t, accumulatedReport, "accumulated report should not be nil ")
	//sort accumulatedReport report slices
	sort.Slice(accumulatedReport.Vulnerabilities, func(i, j int) bool {
		return strings.Compare(accumulatedReport.Vulnerabilities[i].Name, accumulatedReport.Vulnerabilities[j].Name) == -1
	})
	sort.Slice(accumulatedReport.Summary.SeveritiesStats, func(i, j int) bool {
		return strings.Compare(accumulatedReport.Summary.SeveritiesStats[i].Severity, accumulatedReport.Summary.SeveritiesStats[j].Severity) == -1
	})
	sort.Slice(accumulatedReport.Summary.Context, func(i, j int) bool {
		return strings.Compare(accumulatedReport.Summary.Context[i].Attribute, accumulatedReport.Summary.Context[j].Attribute) == -1
	})
	/* uncomment to update expected result
	file, _ := json.MarshalIndent(accumulatedReport, "", "")
	_ = ioutil.WriteFile("testdata/expectedScanReport.json", file, 0644)
	*/
	//compare accumulatedReport with expected
	diff := gcmp.Diff(accumulatedReport, &expectedScanReport,
		cmpopts.IgnoreFields(cs.ScanResultReportV1{}, "PaginationInfo", "Timestamp", "ContainerScanID"),
		cmpopts.IgnoreFields(cs.CommonContainerScanSummaryResult{}, "ContainerScanID", "Timestamp"),
		cmpopts.IgnoreFields(cs.CommonContainerVulnerabilityResult{}, "ContainerScanID", "Timestamp", "Context"))

	assert.Empty(t, diff, "actual compare with expected should not have diffs")
}

//go:embed testdata/testCaseVulnerabilities.json
var testCaseVulnerabilitiesBytes []byte

func TestSplit2Chunks(t *testing.T) {
	vulnerabilitiesTestCase := []cs.CommonContainerVulnerabilityResult{}
	if err := json.Unmarshal(testCaseVulnerabilitiesBytes, &vulnerabilitiesTestCase); err != nil {
		t.Error("Could not read testCaseVulnerabilities.json", err)
	}
	numOfVulnerabilities := len(vulnerabilitiesTestCase)
	tests := map[int]splitResults{
		//normal chunk size - expected splitting
		30000: {totalReceived: numOfVulnerabilities,
			numOfChunks:    3,
			maxChunkSize:   29800,
			minChunkSize:   16370,
			maxChunkLength: 12,
			minChunkLength: 9,
		},
		//big chunk size - expected splitting
		60000: {totalReceived: numOfVulnerabilities,
			numOfChunks:    2,
			maxChunkSize:   58098,
			minChunkSize:   14563,
			maxChunkLength: 25,
			minChunkLength: 8,
		},
		//big chunk size - expected splitting
		15000: {totalReceived: numOfVulnerabilities,
			numOfChunks:    8,
			maxChunkSize:   14332,
			minChunkSize:   2334,
			maxChunkLength: 6,
			minChunkLength: 1,
		},
		//huge chunk size - no splitting expected
		300000: {totalReceived: numOfVulnerabilities,
			numOfChunks:    1,
			maxChunkSize:   72659,
			minChunkSize:   72659,
			maxChunkLength: 33,
			minChunkLength: 33,
		},
		//tiny chunk size expect one item in each chunk
		300: {totalReceived: numOfVulnerabilities,
			numOfChunks:    33,
			maxChunkSize:   3492,
			minChunkSize:   1803,
			maxChunkLength: 1,
			minChunkLength: 1,
		},
	}
	for chunkSize, expectedResults := range tests {
		results := testSplit(chunkSize, vulnerabilitiesTestCase)
		assert.Equal(t, expectedResults.totalReceived, results.totalReceived, "number of received must be the same as number of item sent")
		assert.Equal(t, expectedResults.numOfChunks, results.numOfChunks, "numOfChunks must be same as expected numOfChunks")
		assert.Equal(t, expectedResults.maxChunkSize, results.maxChunkSize, "numOfChunks must be same as expected maxChunkSize")
		assert.Equal(t, expectedResults.minChunkSize, results.minChunkSize, "numOfChunks must be same as expected minChunkSize")
		assert.Equal(t, expectedResults.maxChunkLength, results.maxChunkLength, "numOfChunks must be same as expected maxChunkLength")
		assert.Equal(t, expectedResults.minChunkLength, results.minChunkLength, "numOfChunks must be same as expected maxChunkLength")

	}

}

type splitResults struct {
	totalReceived  int
	numOfChunks    int
	maxChunkSize   int
	minChunkSize   int
	maxChunkLength int
	minChunkLength int
}

func startTestClientServer(requestUrl string, handler http.Handler) (*httptest.Server, error) {
	l, err := net.Listen("tcp", requestUrl)
	if err != nil {
		return nil, err
	}
	testServer := httptest.NewUnstartedServer(handler)
	testServer.Listener.Close()
	testServer.Listener = l
	testServer.Start()
	return testServer, nil
}

func testSplit(chunkSize int, vulns []cs.CommonContainerVulnerabilityResult) splitResults {
	results := splitResults{}
	chunksChan, _ := armoUtils.SplitSlice2Chunks(vulns, chunkSize, 10)
	testWg := sync.WaitGroup{}
	testWg.Add(1)
	go func(results *splitResults) {
		defer testWg.Done()
		for v := range chunksChan {
			results.numOfChunks++
			vSize := armoUtils.JSONSize(v)
			vLen := len(v)
			results.totalReceived += vLen
			if results.maxChunkSize < vSize {
				results.maxChunkSize = vSize
			}
			if results.minChunkSize > vSize || results.minChunkSize == 0 {
				results.minChunkSize = vSize
			}
			if results.maxChunkLength < vLen {
				results.maxChunkLength = vLen
			}
			if results.minChunkLength > vLen || results.minChunkLength == 0 {
				results.minChunkLength = vLen
			}
		}
	}(&results)
	testWg.Wait()
	return results
}
