package docs

import (
	"github.com/armosec/armoapi-go/apis"
)

/*
An empty response.

swagger:response
*/
type emptyResponse struct{}

/*
The service is ready to accept requests.

swagger:response
*/
type readinessReady struct{}

/*
The service is not ready to accept requests.

swagger:response
*/
type readinessServiceUnavailable struct{}

/*
swagger:route GET /v1/readiness probes getReadiness
Checks if service is ready to check images.

Responses:
  202: readinessReady
  503: readinessServiceUnavailable
*/

/*
swagger:route HEAD /v1/ready probes headReady
Checks if the HTTP server is ready to accept requests.

Responses:
  202: readinessReady
*/

/*
Body of the Ready request.

Example: db is ready
Default: something
*/
type postReadyRequestBody string

/*
A request to set the service status to “Ready”.

In: Body
Example: test value

swagger:parameters postReady
*/
type postReadyRequest struct {
	Body postReadyRequestBody
}

/*
Malformed request.

swagger:response
*/
type postReadyBadRequest struct{}

/*
swagger:route POST /v1/ready probes postReady
Sets the service’s readiness status.

Instruct the server to report that it is ready to scan images.

Consumes:
  - text/plain

Responses:
  202: emptyResponse
  400: postReadyBadRequest
*/

/*
Example:  {"imageTag": "nginx:latest", "wlid": "wlid://cluster-marina/namespace-default/deployment-nginx", "isScanned": False, "containerName": "nginx", "jobID": "7b04592b-665a-4e47-a9c9-65b2b3cabb49"}

swagger:parameters postScanImage
*/
type postScanImageParams struct {
	// In: body
	Body apis.WebsocketScanCommand
}

/*
Response body of a response that a POST Scan Image request has been Accepted.

Example: scan request accepted
*/
type postScanImageAcceptedResponseBody string

/*
A response to scan an Image has been accepted.

The request will be processed asynchronously.

swagger:response postScanImageAccepted
*/
type postScanImageAccepted struct {
	// In: body
	Body postScanImageAcceptedResponseBody
}

/*
A response body of a response that an incoming POST Scan Image request was malformed.

Example: image tag and image hash are missing
*/
type postScanImageBadRequestResponseBody string

/*
A response that signals that an incoming POST scanImage request was malformed.

swagger:response postScanImageBadRequest
*/
type postScanImageBadRequest struct {
	// In: body
	Body postScanImageAcceptedResponseBody
}

/*
swagger:route POST /v1/scanImage scanning postScanImage
Schedules an image scan.

Schedules an image described in the request body to be scanned for vulnerabilities.

Responses:
  202: postScanImageAccepted
  400: postScanImageBadRequest
*/

/*
A request to run a command related to the vulnerability database.

swagger:parameters postDBCommand
*/
type postDBCommandRequest struct {
	// The commands to run on a vulnerability database
	//
	// In: body
	Body apis.DBCommand
}

/*
Response body of the postDBCommandAccepted
*/
type postDBCommandAcceptedResponseBody string

/*
A response signaling that a DB-related command has been accepted.

swagger:response postDBCommandAccepted
*/
type postDBCommandAccepted struct {
	// In: body
	Body postDBCommandAcceptedResponseBody
}

type postDBCommandBadRequestResponseBody string

/*
A response signaling that a request with a DB-related command was malformed.

swagger:response postDBCommandBadRequest
*/
type postDBCommandBadRequest struct {
	// In: body
	Body postDBCommandBadRequestResponseBody
}

/*
swagger:route POST /v1/DBCommand database postDBCommand
Schedules a command related to the vulnerability database to be run.

Used to update the vulnerability database.

Responses:
  202: postDBCommandAccepted
  400: postDBCommandBadRequest
*/
