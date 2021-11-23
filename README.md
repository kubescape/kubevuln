# Configuration

## Environment variables

### OCImage
* OCIMAGE_URL : http://localhost:8080 - optional - will ignore getting bash commands and various enhanchments to it

### Clair
* CLAIR_URL : http://localhost:6060 - mandatory

### Event Reciever
* CA_EVENT_RECEIVER_HTTP : http://localhost:7555 - mandatory

### ca customer GUID
* CA_CUSTOMER_GUID : customer GUID - mandatory

### print final post json 
* PRINT_POST_JSON : any value - optional

git config --global url."ssh://git@github.com/armosec/".insteadOf "https://github.com/armosec/"
go env -w GOPRIVATE=github.com/armosec
