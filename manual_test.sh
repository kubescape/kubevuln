#!/bin/bash

echo "=== Manual KubeVuln API Test ==="
echo

# Check if server is running
echo "🔍 Checking if server is running..."
if ! curl -s http://localhost:8080/v1/readiness > /dev/null; then
    echo "❌ Server is not running on localhost:8080"
    echo "Please start the server first: ./kubevuln"
    exit 1
fi

echo "✅ Server is running!"

echo
echo "📋 Available endpoints:"
echo "   GET  /v1/readiness     - Check if server is ready"
echo "   GET  /v1/liveness      - Check if server is alive"
echo "   POST /v1/registry-scan - Scan an image from registry"
echo "   POST /v1/container-scan - Scan a container"
echo "   POST /v1/sbom-calculation - Generate SBOM"
echo

# Test readiness
echo "🧪 Testing readiness endpoint..."
curl -s http://localhost:8080/v1/readiness
echo

# Test liveness
echo "🧪 Testing liveness endpoint..."
curl -s http://localhost:8080/v1/liveness
echo

echo
echo "📤 Testing registry scan with nginx:latest..."

# Create test payload
cat > nginx_scan.json << 'EOF'
{
  "session": {
    "jobIDs": ["manual-test-123"],
    "timestamp": "2024-01-01T00:00:00Z",
    "rootJobID": "manual-test-123",
    "action": "vulnerability-scan"
  },
  "imageTag": "nginx:latest",
  "wlid": "wlid://cluster-test/namespace-default/deployment-nginx",
  "isScanned": false,
  "containerName": "nginx",
  "jobID": "manual-test-123",
  "parentJobID": "manual-test-123",
  "actionIDN": 1
}
EOF

echo "📤 Sending registry scan request..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST http://localhost:8080/v1/registry-scan \
  -H "Content-Type: application/json" \
  -d @nginx_scan.json)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n -1)

echo "📥 Response Code: $HTTP_CODE"
echo "📥 Response Body: $RESPONSE_BODY"

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Registry scan request accepted!"
    echo
    echo "⏳ The server is now processing nginx:latest..."
    echo "   - Syft will generate an SBOM"
    echo "   - Dive will analyze image layers"
    echo "   - Results will be saved to dive-results/nginx-dive.json"
    echo
    echo "🔍 Monitor for dive results:"
    echo "   watch -n 5 'ls -la dive-results/ 2>/dev/null || echo \"No dive results yet\"'"
    echo
    echo "📊 Check dive results when ready:"
    echo "   jq '.image | {size: .sizeBytes, efficiency: .efficiencyScore}' dive-results/nginx-dive.json"
else
    echo "❌ Registry scan request failed"
fi

# Cleanup
rm -f nginx_scan.json

echo
echo "🎉 Manual test completed!" 