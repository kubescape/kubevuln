# Kubevuln
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/kubescape/kubevuln/badge)](https://securityscorecards.dev/viewer/?uri=github.com/kubescape/kubevuln)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fkubescape%2Fkubevuln.svg?type=shield&issueType=license)](https://app.fossa.com/projects/git%2Bgithub.com%2Fkubescape%2Fkubevuln?ref=badge_shield&issueType=license)


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
       "kubevulnURL": "127.0.0.1:8080",
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
   `export PORT=8080`  

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
                     "PORT": "8080",
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
We configure the Kubevuln to listen to port 8080, and define the configuration in the clusterData.json file [as mentioned above](https://github.com/kubescape/kubevuln#configuration).
</details>
 
