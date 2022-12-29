# Kubevuln
The Kubevuln component is an in-cluster component of the Kubescape security platform.  
It [scans container images for vulnerabilities](https://www.armosec.io/blog/code-repository-container-image-registry-scanning/?utm_source=github&utm_medium=repository), using Grype as its engine.

## Build Kubevuln
To build kubevuln with its dependencies run: `make`

## Configuration
1. Load config file using the `CONFIG` environment variable   

   `export CONFIG=path/to/clusterData.json`  

   <details><summary>example/clusterData.json</summary>
   
   ```json5 
   {
       "gatewayWebsocketURL": "127.0.0.1:8001",
       "gatewayRestURL": "127.0.0.1:8002",
       "kubevulnURL": "127.0.0.1:8081",
       "kubescapeURL": "127.0.0.1:8080",
       "eventReceiverRestURL": "https://report.armo.cloud",
       "eventReceiverWebsocketURL": "wss://report.armo.cloud",
       "rootGatewayURL": "wss://ens.euprod1.cyberarmorsoft.com/v1/waitfornotification",
       "accountID": "*********************",
       "clusterName": "******" 
      } 
   ``` 
   </details>
   
2. Set the `PORT` environment variable to 8081  
   `export PORT=8081`  

## Environment Variables

Check out `scanner/environmentvariables.go`

## VS code configuration samples

You can use the samples files below to setup your [VS code](https://www.armosec.io/blog/securing-ci-cd-pipelines-security-gates/?utm_source=github&utm_medium=repository) environment for building and debugging purposes.

<details><summary>.vscode/launch.json</summary>

```json5
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch Package",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "program":  "${workspaceRoot}",
                 "env": {
                     "PORT": "8081",
                     "NAMESPACE": "kubescape",
                     "CONFIG": "${workspaceRoot}/.vscode/clusterData.json",
            },
            "args": [
                "-alsologtostderr", "-v=4", "2>&1"
            ]
        }
    ]
}
```
We configure the Kubevuln to listen to port 8081, and define the configuration in the clusterData.json file [as mentioned above](https://github.com/kubescape/kubevuln#configuration).
</details>

## Make option
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
