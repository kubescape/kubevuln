import requests
import json

http = 'http'
url = 'localhost:8080'
payload = {
    "imageTag": "nginx:latest",

	"wlid": "wlid://cluster-marina/namespace-default/deployment-nginx",
    "isScanned": False,
	"containerName": "nginx",
    "jobID": "7b04592b-665a-4e47-a9c9-65b2b3cabb49"
}

requests.post(f'{http}://{url}/v1/scanImage',json=json.dumps(payload))