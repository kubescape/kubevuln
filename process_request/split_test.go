package process_request

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	cs "github.com/armosec/cluster-container-scanner-api/containerscan"
)

//set required env vars
var _ = (func() interface{} {
	os.Setenv("CA_CUSTOMER_GUID", "e57ec5a0-695f-4777-8366-1c64fada00a0")
	os.Setenv("CA_EVENT_RECEIVER_HTTP", "http://localhost:7555")
	return nil
}())

type splitResults struct {
	totalReceived  int
	numOfChunks    int
	maxChunkSize   int
	minChunkSize   int
	maxChunkLength int
	minChunkLength int
}

func TestSplit2Chunks(t *testing.T) {
	//load vulnerabilities test case
	file, _ := ioutil.ReadFile("test_vulnerabilities.json")
	vulnerabilitiesTestCase := []cs.CommonContainerVulnerabilityResult{}
	err := json.Unmarshal([]byte(file), &vulnerabilitiesTestCase)
	if err != nil {
		t.Error("Could not read configuration", err)

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

func testSplit(chunkSize int, vulns []cs.CommonContainerVulnerabilityResult) splitResults {
	results := splitResults{}
	chunksChan := make(chan []cs.CommonContainerVulnerabilityResult, 10)
	wg := sync.WaitGroup{}
	split2Chunks(vulns, chunkSize, chunksChan, &wg)
	testWg := sync.WaitGroup{}
	testWg.Add(1)
	go func(results *splitResults) {
		defer testWg.Done()
		for v := range chunksChan {
			results.numOfChunks++
			vSize := jsonSize(v)
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
	wg.Wait()
	close(chunksChan)
	testWg.Wait()
	return results
}
