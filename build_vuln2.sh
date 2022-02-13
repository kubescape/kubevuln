#!/usr/bin/env bash
set -ex

export WTAG=test

# dep ensure
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o k8s-ca-vuln-scan .
chmod +x k8s-ca-vuln-scan

docker build --no-cache -f Dockerfile.Test -t quay.io/armosec/k8s-ca-vuln-scan-ubi:$WTAG .
rm -rf k8s-ca-vuln-scan
# docker push quay.io/armosec/k8s-ca-vuln-scan-ubi:$WTAG

echo "update vuln-scan"

kubectl -n armo-system patch  deployment armo-vuln-scan -p '{"spec": {"template": {"spec": { "containers": [{"name": "armo-vuln-scan", "imagePullPolicy": "Never"}]}}}}' || true
kubectl -n armo-system set image deployment/armo-vuln-scan armo-vuln-scan=quay.io/armosec/k8s-ca-vuln-scan-ubi:$WTAG || true
kubectl -n armo-system delete pod $(kubectl get pod -n armo-system | grep vuln-scan |  awk '{print $1}')
kubectl -n armo-system logs -f $(kubectl get pod -n armo-system | grep vuln-scan |  awk '{print $1}')
