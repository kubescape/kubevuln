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
    exit 1
fi

print_success "Found kubevuln pod: $POD_NAME"

# Setup port forwarding
print_status "Setting up port forwarding from localhost:$LOCAL_PORT to $POD_NAME:$REMOTE_PORT..."
kubectl port-forward -n $NAMESPACE $POD_NAME $LOCAL_PORT:$REMOTE_PORT &
PORT_FORWARD_PID=$!

# Wait for port forwarding to be ready
sleep 3

print_success "Port forwarding established (PID: $PORT_FORWARD_PID)"

# Test 1: Health checks
print_status "=== Testing Health Endpoints ==="
LIVENESS_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/liveness_response http://localhost:$LOCAL_PORT/v1/liveness)
if [ "$LIVENESS_RESPONSE" = "200" ]; then
    print_success "Liveness check passed"
else
    print_error "Liveness check failed (HTTP $LIVENESS_RESPONSE)"
    exit 1
fi

# Test 2: Private ECR Images
print_status "=== Testing Private ECR Images ==="

# Pre-calculate timestamp and IDs
TIMESTAMP=$(date -Iseconds)
EPOCH=$(date +%s)

# Test with scanner image (private ECR)
print_status "Testing SBOM generation with private ECR image: scanner..."
KUBEVULN_PAYLOAD=$(cat << EOF
{
  "session": {
    "jobIDs": ["scanner-${EPOCH}", "scanner-${EPOCH}-2"],
    "timestamp": "${TIMESTAMP}",
    "rootJobID": "scanner-${EPOCH}",
    "action": "vulnerability-scan"
  },
  "imageTag": "782681689401.dkr.ecr.ap-south-1.amazonaws.com/cqs-k8-artifacts/scanner:latest",
  "wlid": "wlid://cluster-test/namespace-cyberqshield/deployment-scanner",
  "isScanned": false,
  "containerName": "scanner",
  "jobID": "scanner-${EPOCH}-2",
  "parentJobID": "scanner-${EPOCH}",
  "actionIDN": 1,
  "credentialsList": []
}
EOF
)

KUBEVULN_RESPONSE=$(curl -s -w "%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  -d "$KUBEVULN_PAYLOAD" \
  -o /tmp/kubevuln_response \
  http://localhost:$LOCAL_PORT/v1/generateSBOM)

if [ "$KUBEVULN_RESPONSE" = "200" ]; then
    print_success "Private ECR scanner SBOM generation request accepted"
    echo "Response: $(cat /tmp/kubevuln_response)"
else
    print_error "Private ECR scanner SBOM generation failed (HTTP $KUBEVULN_RESPONSE)"
    cat /tmp/kubevuln_response
fi

# Monitor logs for private image processing
print_status "=== Monitoring Pod Logs for Private Images ==="
print_warning "Monitoring logs for 60 seconds to see private image processing..."

timeout 60s kubectl logs -f $POD_NAME -n $NAMESPACE --tail=50 || true

# Check for scan reports
print_status "=== Checking for Private Image Scan Reports ==="
print_status "Waiting 10 seconds for reports to be created..."
sleep 10

SCAN_REPORTS=$(kubectl get scanreports -n $NAMESPACE --no-headers 2>/dev/null | wc -l)
if [ "$SCAN_REPORTS" -gt 0 ]; then
    print_success "Found $SCAN_REPORTS ScanReport(s) in namespace $NAMESPACE"
    
    print_status "Scan reports created:"
    kubectl get scanreports -n $NAMESPACE
    
    # Check for dive and trufflehog reports separately
    DIVE_REPORTS=$(kubectl get scanreports -n $NAMESPACE -l tool=dive --no-headers 2>/dev/null | wc -l)
    TRUFFLEHOG_REPORTS=$(kubectl get scanreports -n $NAMESPACE -l tool=trufflehog --no-headers 2>/dev/null | wc -l)
    
    print_success "Found $DIVE_REPORTS dive reports and $TRUFFLEHOG_REPORTS trufflehog reports"
else
    print_warning "No ScanReports found - private images might still be processing"
fi

# Summary
print_status "=== Private Image Test Summary ==="
print_success "✅ Health checks completed"
print_success "✅ Private ECR image SBOM request sent"
print_success "✅ Log monitoring completed"

print_success "Private image test automation completed!" 