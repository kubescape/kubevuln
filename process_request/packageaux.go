package process_request

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

//Pkg represent data from dpkg/status
type Pkg struct {
	Src  string
	Name string
}

//resets a package data
func (pk *Pkg) reset() {
	pk.Name = ""
	pk.Src = ""
}

const (
	packageprefix = "Package: "
	srcprefix     = "Source: " //source package
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

/* clairPkgName2packagename -

DPKG code only!!
*/

func clairPkgName2packagename(packageType string, file []byte) (map[string][]string, error) {
	switch packageType {
	case "dpkg":
		return dpkgMapper(file)
	default:
		return nil, fmt.Errorf("not implement for %s", packageType)
	}

}

/* dpkgMapper
SEE: https://github.com/quay/clair/blob/release-2.0/ext/featurefmt/dpkg/dpkg.go

currently clair(v2) looks at /var/lib/dpkg/status
and takes Package name (Package: x) and translate it to Source: y
so we see y and not x

in this function we reverse this process, notice that while x->y is 1:1 y->x is 1:n (1 to many)
for now we'll consider this as acceptable...
*/

func dpkgMapper(file []byte) (map[string][]string, error) {
	res := make(map[string][]string, 0)
	tmp := make([]Pkg, 0)

	scanner := bufio.NewScanner(bytes.NewReader(file))

	tmppkg := Pkg{}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, packageprefix) {
			tmppkg.Name = strings.TrimSpace(strings.TrimPrefix(line, packageprefix))
		} else if strings.HasPrefix(line, srcprefix) {
			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line, -1)[0]
			md := map[string]string{}
			//takes the regexp result and categorize the result(name,version and etc.)
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			tmppkg.Src = md["name"]
			tmp = append(tmp, tmppkg)
			tmppkg.reset()
		} else if line == "" {
			tmppkg.reset()
		}
	}

	for _, v := range tmp {
		if _, isOk := res[v.Src]; !isOk {
			res[v.Src] = make([]string, 0)
		}
		res[v.Src] = append(res[v.Src], v.Name)
	}

	return res, nil
}
