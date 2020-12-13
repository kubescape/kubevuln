package process_request

import (
	"fmt"
	"os"

	"github.com/optiopay/klar/clair"
	"github.com/optiopay/klar/docker"
)

type vulnerabilityResult struct {
	LayerCount      int
	Vulnerabilities map[string][]*clair.Vulnerability
}

func getClairScanResults(containerImageRefString string) (string, error) {
	dockerConfiguration := docker.Config{ImageName: containerImageRefString}

	image, err := docker.NewImage(&dockerConfiguration)
	if err != nil {
		return "", err
	}

	err = image.Pull()
	if err != nil {
		return "", err
	}

	output := vulnerabilityResult{
		Vulnerabilities: make(map[string][]*clair.Vulnerability),
	}

	if len(image.FsLayers) == 0 {
		return "", fmt.Errorf("problem pulling %s", containerImageRefString)
	}

	output.LayerCount = len(image.FsLayers)

	var vs []*clair.Vulnerability
	for _, ver := range []int{1, 3} {
		c := clair.NewClair("http://35.246.251.137:6060", ver, 30)
		vs, err = c.Analyse(image)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to analyze using API v%d: %s\n", ver, err)
		} else {
			if !conf.JSONOutput {
				fmt.Printf("Got results from Clair API v%d\n", ver)
			}
			break
		}
	}
	if err != nil {
		fail("Failed to analyze, exiting")
	}

	vsNumber := 0

	numVulnerabilites := len(vs)
	vs = filterWhitelist(whitelist, vs, image.Name)
	numVulnerabilitiesAfterWhitelist := len(vs)
	groupBySeverity(vs)

	if conf.JSONOutput {
		vsNumber = jsonFormat(conf, output)
	} else {
		if numVulnerabilitiesAfterWhitelist < numVulnerabilites {
			//display how many vulnerabilities were whitelisted
			fmt.Printf("Whitelisted %d vulnerabilities\n", numVulnerabilites-numVulnerabilitiesAfterWhitelist)
		}
		fmt.Printf("Found %d vulnerabilities\n", len(vs))
		switch style := conf.FormatStyle; style {
		case "table":
			vsNumber = tableFormat(conf, vs)
		default:
			vsNumber = standardFormat(conf, vs)
		}
	}

	//clair.Analyze
	return "Not implemented yet", nil
}
