# Configuration

## Environment variables

### OCImage
* OCIMAGE_URL : http://localhost:8080 - mandatory

### Clair
* CLAIR_URL : http://localhost:6060 - mandatory

### Event Reciever
* EVENT_RECIEVER_URL : http://localhost:7555 - mandatory

### ca customer GUID
* CA_CUSTOMER_GUID : customer GUID - mandatory

### print final post json 
* PRINT_POST_JSON : any value - optional

git config --global url."ssh://git@github.com/armosec/".insteadOf "https://github.com/armosec/"
go env -w GOPRIVATE=github.com/armosec
