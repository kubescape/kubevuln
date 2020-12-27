package process_request

import (
	"fmt"
	"strings"
)

func apkInstallDbParser(dbRaw *[]byte) (*map[string][]string, error) {
	dbLines := strings.Split(string(*dbRaw), "\n")
	var pack string
	var path string
	apkInstallDbMap := make(map[string][]string)
	for _, line := range dbLines {
		if strings.HasPrefix(line, "P:") {
			pack = line[2:]
		}
		if strings.HasPrefix(line, "F:") {
			path = "/" + line[2:]
		}
		if strings.HasPrefix(line, "R:") {
			if len(pack) == 0 || len(path) == 0 {
				return nil, fmt.Errorf("corrupted apk db")
			}
			apkInstallDbMap[pack] = append(apkInstallDbMap[pack], path+"/"+line[2:])
		}
	}
	return &apkInstallDbMap, nil
}
