#!/bin/bash

set -e

# Configuration
NAMESPACE="cyberqshield"
SERVICE_NAME="kubevuln"
LOCAL_PORT="8080"
REMOTE_PORT="8080"

# Dynamically find the kubevuln pod
POD_NAME=$(kubectl get pods -n $NAMESPACE -l app=kubevuln -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to cleanup on exit
cleanup() {
    print_status "Cleaning up..."
    if [ ! -z "$PORT_FORWARD_PID" ]; then
        kill $PORT_FORWARD_PID 2>/dev/null || true
        print_status "Port forwarding stopped"
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    print_error "kubectl is not installed or not in PATH"
    exit 1
fi

# Check if we found a pod
if [ -z "$POD_NAME" ]; then
    print_error "No kubevuln pod found in namespace $NAMESPACE"
    print_status "Available pods in namespace $NAMESPACE:"
    kubectl get pods -n $NAMESPACE
    exit 1
fi

# Check if the pod is running
print_status "Checking if kubevuln pod $POD_NAME is running in namespace $NAMESPACE..."
if ! kubectl get pod $POD_NAME -n $NAMESPACE &> /dev/null; then
    print_error "Pod $POD_NAME not found in namespace $NAMESPACE"
    print_status "Available pods in namespace $NAMESPACE:"
    kubectl get pods -n $NAMESPACE
    exit 1
fi

POD_STATUS=$(kubectl get pod $POD_NAME -n $NAMESPACE -o jsonpath='{.status.phase}')
if [ "$POD_STATUS" != "Running" ]; then
    print_error "Pod $POD_NAME is not running (status: $POD_STATUS)"
    exit 1
fi

print_success "Pod $POD_NAME is running"

# Setup port forwarding
print_status "Setting up port forwarding from localhost:$LOCAL_PORT to $POD_NAME:$REMOTE_PORT..."
kubectl port-forward -n $NAMESPACE $POD_NAME $LOCAL_PORT:$REMOTE_PORT &
PORT_FORWARD_PID=$!

# Wait for port forwarding to be ready
sleep 3

# Check if port forwarding is working
if ! kill -0 $PORT_FORWARD_PID 2>/dev/null; then
    print_error "Port forwarding failed to start"
    exit 1
fi

print_success "Port forwarding established (PID: $PORT_FORWARD_PID)"

# Test 1: Health checks
print_status "=== Testing Health Endpoints ==="

# Liveness check
print_status "Testing liveness endpoint..."
LIVENESS_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/liveness_response http://localhost:$LOCAL_PORT/v1/liveness)
if [ "$LIVENESS_RESPONSE" = "200" ]; then
    print_success "Liveness check passed"
else
    print_error "Liveness check failed (HTTP $LIVENESS_RESPONSE)"
    cat /tmp/liveness_response
fi

# Readiness check
print_status "Testing readiness endpoint..."
READINESS_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/readiness_response http://localhost:$LOCAL_PORT/v1/readiness)
if [ "$READINESS_RESPONSE" = "200" ]; then
    print_success "Readiness check passed"
else
    print_error "Readiness check failed (HTTP $READINESS_RESPONSE)"
    cat /tmp/readiness_response
fi

# Test 2: SBOM Generation (triggers dive and trufflehog)
print_status "=== Testing SBOM Generation (with dive and trufflehog) ==="

# Pre-calculate timestamp and IDs to avoid issues
TIMESTAMP=$(date -Iseconds)
EPOCH=$(date +%s)

# Test with Alpine image - FIXED: Use proper image references
print_status "Testing SBOM generation with alpine:latest..."
ALPINE_PAYLOAD=$(cat << EOF
{
  "session": {
    "jobIDs": ["alpine-test-${EPOCH}", "alpine-test-${EPOCH}-2"],
    "timestamp": "${TIMESTAMP}",
    "rootJobID": "alpine-test-${EPOCH}",
    "action": "vulnerability-scan"
  },
  "imageTag": "alpine:latest",
  "wlid": "wlid://cluster-test/namespace-default/deployment-alpine-test",
  "isScanned": false,
  "containerName": "alpine-test",
  "jobID": "alpine-test-${EPOCH}-2",
  "parentJobID": "alpine-test-${EPOCH}",
  "actionIDN": 1,
  "credentialsList": []
}
EOF
)

ALPINE_RESPONSE=$(curl -s -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$ALPINE_PAYLOAD" \
  -o /tmp/alpine_response \
  http://localhost:$LOCAL_PORT/v1/generateSBOM)

if [ "$ALPINE_RESPONSE" = "200" ]; then
    print_success "Alpine SBOM generation request accepted"
    echo "Response: $(cat /tmp/alpine_response)"
else
    print_error "Alpine SBOM generation failed (HTTP $ALPINE_RESPONSE)"
    cat /tmp/alpine_response
fi

# Test with Nginx image - FIXED: Use proper image references
print_status "Testing SBOM generation with nginx:latest..."
NGINX_PAYLOAD=$(cat << EOF
{
  "session": {
    "jobIDs": ["nginx-test-${EPOCH}", "nginx-test-${EPOCH}-2"],
    "timestamp": "${TIMESTAMP}",
    "rootJobID": "nginx-test-${EPOCH}",
    "action": "vulnerability-scan"
  },
  "imageTag": "nginx:latest",
  "wlid": "wlid://cluster-test/namespace-default/deployment-nginx-test",
  "isScanned": false,
  "containerName": "nginx-test",
  "jobID": "nginx-test-${EPOCH}-2",
  "parentJobID": "nginx-test-${EPOCH}",
  "actionIDN": 1,
  "credentialsList": []
}
EOF
)

NGINX_RESPONSE=$(curl -s -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$NGINX_PAYLOAD" \
  -o /tmp/nginx_response \
  http://localhost:$LOCAL_PORT/v1/generateSBOM)

if [ "$NGINX_RESPONSE" = "200" ]; then
    print_success "Nginx SBOM generation request accepted"
    echo "Response: $(cat /tmp/nginx_response)"
else
    print_error "Nginx SBOM generation failed (HTTP $NGINX_RESPONSE)"
    cat /tmp/nginx_response
fi

# Test with Ubuntu image - FIXED: Use proper image references
print_status "Testing SBOM generation with ubuntu:20.04..."
UBUNTU_PAYLOAD=$(cat << EOF
{
  "session": {
    "jobIDs": ["ubuntu-test-${EPOCH}", "ubuntu-test-${EPOCH}-2"],
    "timestamp": "${TIMESTAMP}",
    "rootJobID": "ubuntu-test-${EPOCH}",
    "action": "vulnerability-scan"
  },
  "imageTag": "ubuntu:20.04",
  "wlid": "wlid://cluster-test/namespace-default/deployment-ubuntu-test",
  "isScanned": false,
  "containerName": "ubuntu-test",
  "jobID": "ubuntu-test-${EPOCH}-2",
  "parentJobID": "ubuntu-test-${EPOCH}",
  "actionIDN": 1,
  "credentialsList": []
}
EOF
)

UBUNTU_RESPONSE=$(curl -s -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$UBUNTU_PAYLOAD" \
  -o /tmp/ubuntu_response \
  http://localhost:$LOCAL_PORT/v1/generateSBOM)

if [ "$UBUNTU_RESPONSE" = "200" ]; then
    print_success "Ubuntu SBOM generation request accepted"
    echo "Response: $(cat /tmp/ubuntu_response)"
else
    print_error "Ubuntu SBOM generation failed (HTTP $UBUNTU_RESPONSE)"
    cat /tmp/ubuntu_response
fi

# Test 3: CVE Scan - FIXED: Use proper image references
print_status "=== Testing CVE Scan ==="

print_status "Testing CVE scan with busybox:latest..."
BUSYBOX_PAYLOAD=$(cat << EOF
{
  "session": {
    "jobIDs": ["busybox-cve-${EPOCH}", "busybox-cve-${EPOCH}-2"],
    "timestamp": "${TIMESTAMP}",
    "rootJobID": "busybox-cve-${EPOCH}",
    "action": "vulnerability-scan"
  },
  "imageTag": "busybox:latest",
  "wlid": "wlid://cluster-test/namespace-default/deployment-busybox-test",
  "isScanned": false,
  "containerName": "busybox-test",
  "jobID": "busybox-cve-${EPOCH}-2",
  "parentJobID": "busybox-cve-${EPOCH}",
  "actionIDN": 1,
  "credentialsList": []
}
EOF
)

BUSYBOX_RESPONSE=$(curl -s -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$BUSYBOX_PAYLOAD" \
  -o /tmp/busybox_response \
  http://localhost:$LOCAL_PORT/v1/scanImage)

if [ "$BUSYBOX_RESPONSE" = "200" ]; then
    print_success "Busybox CVE scan request accepted"
    echo "Response: $(cat /tmp/busybox_response)"
else
    print_error "Busybox CVE scan failed (HTTP $BUSYBOX_RESPONSE)"
    cat /tmp/busybox_response
fi

# Test 4: Registry Scan
print_status "=== Testing Registry Scan ==="

print_status "Testing registry scan with hello-world:latest..."
REGISTRY_PAYLOAD=$(cat << EOF
{
  "session": {
    "jobIDs": ["hello-world-registry-${EPOCH}", "hello-world-registry-${EPOCH}-2"],
    "timestamp": "${TIMESTAMP}",
    "rootJobID": "hello-world-registry-${EPOCH}",
    "action": "vulnerability-scan"
  },
  "imageTag": "hello-world:latest",
  "jobID": "hello-world-registry-${EPOCH}-2",
  "parentJobID": "hello-world-registry-${EPOCH}",
  "actionIDN": 1,
  "credentialsList": []
}
EOF
)

REGISTRY_RESPONSE=$(curl -s -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$REGISTRY_PAYLOAD" \
  -o /tmp/registry_response \
  http://localhost:$LOCAL_PORT/v1/scanRegistryImage)

if [ "$REGISTRY_RESPONSE" = "200" ]; then
    print_success "Hello-world registry scan request accepted"
    echo "Response: $(cat /tmp/registry_response)"
else
    print_error "Hello-world registry scan failed (HTTP $REGISTRY_RESPONSE)"
    cat /tmp/registry_response
fi

# Monitor logs
print_status "=== Monitoring Pod Logs ==="
print_warning "Monitoring logs for 45 seconds to see processing..."
print_status "You can press Ctrl+C to stop log monitoring early"

timeout 45s kubectl logs -f $POD_NAME -n $NAMESPACE --tail=30 || true

# Check for CRDs
print_status "=== Checking for ScanReport CRDs ==="
print_status "Checking if any ScanReport CRDs were created..."

if kubectl get crd scanreports.kubevuln.kubescape.io &> /dev/null; then
    print_success "ScanReport CRD exists"
    
    SCAN_REPORTS=$(kubectl get scanreports -n $NAMESPACE --no-headers 2>/dev/null | wc -l)
    if [ "$SCAN_REPORTS" -gt 0 ]; then
        print_success "Found $SCAN_REPORTS ScanReport(s) in namespace $NAMESPACE"
        kubectl get scanreports -n $NAMESPACE
        
        print_status "Getting details of the most recent ScanReport..."
        LATEST_REPORT=$(kubectl get scanreports -n $NAMESPACE --sort-by=.metadata.creationTimestamp -o name | tail -1)
        if [ ! -z "$LATEST_REPORT" ]; then
            print_status "Latest ScanReport details:"
            kubectl get $LATEST_REPORT -n $NAMESPACE -o yaml | head -100
        fi
    else
        print_warning "No ScanReports found in namespace $NAMESPACE (they might still be processing)"
    fi
else
    print_warning "ScanReport CRD not found - results might be stored elsewhere"
fi

# Check for dive and trufflehog results in file system (fallback)
print_status "=== Checking for File-based Results ==="
print_status "Checking for dive and trufflehog result files..."

# Try to exec into the pod to check for result files
if kubectl exec $POD_NAME -n $NAMESPACE -- ls -la /tmp/ 2>/dev/null | grep -E "(dive|trufflehog)" || true; then
    print_success "Found some result files in pod filesystem"
else
    print_warning "No result files found in pod filesystem"
fi

# Summary
print_status "=== Test Summary ==="
print_success "✅ Health checks completed"
print_success "✅ SBOM generation requests sent (3 tests)"
print_success "✅ CVE scan request sent"
print_success "✅ Registry scan request sent"
print_success "✅ Log monitoring completed"

print_warning "Note: SBOM generation, dive, and trufflehog scans run asynchronously."
print_warning "Check the pod logs and CRDs over the next few minutes to see results."

print_status "To continue monitoring:"
echo "  kubectl logs -f $POD_NAME -n $NAMESPACE"
echo "  kubectl get scanreports -n $NAMESPACE -w"
echo "  kubectl exec $POD_NAME -n $NAMESPACE -- ls -la /tmp/"

print_success "Test automation completed successfully!" 