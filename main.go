package main

import "process_request"

// main function
func main() {
	container_name := "python:3.6.12-slim-buster"
	signing_profile := "fdfd"
	process_request.ProcessScanRequest("abcd", container_name, signing_profile)
}
