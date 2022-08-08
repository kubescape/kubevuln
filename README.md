# Configuration

## Environment variables

### OCImage
* OCIMAGE_URL : http://localhost:8080 - optional - will ignore getting bash commands and various enhancements to it


### Event Receiver
* CA_EVENT_RECEIVER_HTTP : http://localhost:7555 - mandatory

### ca customer GUID
* CA_CUSTOMER_GUID : customer GUID - mandatory

### print final post json 
* PRINT_POST_JSON : any value - optional

to test locally:
```
curl -X POST \
   -H 'Content-Type: application/json' \
   -d '{
            "imageTag": "nginx:latest",
            "wlid": "wlid://cluster-minikube/namespace-default/deployment-nginx",
            "isScanned": false,
            "containerName": "nginx",
            "jobID": "7b04592b-665a-4e47-a9c9-65b2b3cabb49"}' \
   http://localhost:8080/v1/scanImage
```