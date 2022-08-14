# Configuration
Load config file using the `CONFIG` environment variable
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







* Build kubevuln with its dependencies
```
make
```

* Build grype
```
make grype
```

* Build kubevuln
```
make build
```

* Run tests
```
make test
```

* Cleanup
```
make clean
```