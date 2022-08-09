package process_request

/*import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
)

func Test(t *testing.T) {
	jsonFile, err := os.Open("grype_mock.json")
	vuln_anchore_report := &models.Document{}

	if err != nil {
		t.Errorf("something wrong!11")
	}
	defer jsonFile.Close()

	byteValue, err := ioutil.ReadAll(jsonFile)

	if err != nil {
		t.Errorf("something wrong 2 !11")
	}
	err = json.Unmarshal(byteValue, vuln_anchore_report)

	if err != nil {
		t.Errorf("something wrong with Unmarshal !11")
	}

	parseLayersPayload(vuln_anchore_report.Source.Target)

}
*/
