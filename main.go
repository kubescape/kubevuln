package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"ca-vuln-scan/catypes"
	"ca-vuln-scan/process_request"

	"github.com/google/uuid"
)

func scanImage(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		customerGuid := req.URL.Query().Get("customerGuid")
		if len(customerGuid) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "missing customerGuid\n")
			return
		}

		solutionGuid := req.URL.Query().Get("solutionGuid")
		if len(solutionGuid) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "missing solutionGuid\n")
			return
		}

		wlid := req.URL.Query().Get("wlid")
		if len(wlid) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "missing wlid\n")
			return
		}

		var requestId []byte
		requestIdStr := req.URL.Query().Get("requestId")
		if len(requestIdStr) == 0 {
			requestId = make([]byte, 16)
			rand.Read(requestId)
		} else {
			requestUUID, err := uuid.Parse(requestIdStr)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "bad requestId (should be in format of UUID)\n")
				return
			}
			requestId, _ = requestUUID.MarshalBinary()
		}

		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "cannot read body\n")
		}

		printUUID, _ := uuid.FromBytes(requestId)
		log.Printf("Got scan request %s for %s", wlid, printUUID.String())

		var requestSP catypes.SigningProfile
		err = json.Unmarshal(body, &requestSP)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "request json could not been parsed\n")
			return
		}

		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "scan request accepted\n")

		log.Printf("Scan request %s is put on processing queue", printUUID.String())

		go process_request.ProcessScanRequestWithS3Upload(requestId, customerGuid, solutionGuid, wlid, &requestSP)
	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "unsupported method\n")
	}
}

func main() {
	http.HandleFunc("/scanImage", scanImage)
	http.ListenAndServe(":8080", nil)
}
