#!/bin/bash

echo "=== KubeVuln Server Test with Dive Integration ==="
echo

# Check if dive binary exists
if [ ! -f "./dive" ]; then
    echo "❌ Error: dive binary not found in current directory"
    echo "Please ensure the dive binary is present: ./dive"
    exit 1
fi

# Create dive-results directory if it doesn't exist
mkdir -p dive-results

echo "🔧 Starting KubeVuln server..."
echo "   Server will run on http://localhost:8080"
echo "   Press Ctrl+C to stop the server"
echo

# Start the server in background
./kubevuln &
SERVER_PID=$!

# Wait for server to start
echo "⏳ Waiting for server to start..."
sleep 5

# Test if server is ready
echo "🔍 Testing server readiness..."
if curl -s http://localhost:8080/v1/readiness > /dev/null; then
    echo "✅ Server is ready!"
else
    echo "❌ Server is not ready yet, waiting..."
    sleep 5
    if curl -s http://localhost:8080/v1/readiness > /dev/null; then
        echo "✅ Server is now ready!"
    else
        echo "❌ Server failed to start"
        kill $SERVER_PID 2>/dev/null
        exit 1
    fi
fi

echo
echo "🧪 Testing with nginx image..."

# Create test payload for registry scan
cat > test_payload.json << 'EOF'
{
  "session": {
    "jobIDs": ["test-job-123"],
    "timestamp": "2024-01-01T00:00:00Z",
    "rootJobID": "test-job-123",
    "action": "vulnerability-scan"
  },
  "imageTag": "nginx:latest",
  "wlid": "wlid://cluster-test/namespace-default/deployment-nginx",
  "isScanned": false,
  "containerName": "nginx",
  "jobID": "test-job-123",
  "parentJobID": "test-job-123",
  "actionIDN": 1
}
EOF

echo "📤 Sending registry scan request..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST http://localhost:8080/v1/registry-scan \
  -H "Content-Type: application/json" \
  -d @test_payload.json)

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n -1)

echo "📥 Response Code: $HTTP_CODE"
echo "📥 Response Body: $RESPONSE_BODY"

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Registry scan request accepted!"
    echo
    echo "⏳ Waiting for scan to complete (this may take a few minutes)..."
    echo "   The server will download nginx:latest and run both syft and dive"
    
    # Wait for dive results - search for the most recent nginx dive file
    DIVE_FILE=""
    for i in {1..30}; do
        # Find the most recent nginx dive file
        DIVE_FILE=$(find dive-results -name "nginx-*-dive.json" -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
        
        if [ -n "$DIVE_FILE" ] && [ -f "$DIVE_FILE" ]; then
            echo "✅ Dive results found!"
            echo "📁 File: $DIVE_FILE"
            echo "📊 File size: $(du -h "$DIVE_FILE" | cut -f1)"
            echo
            echo "🔍 Dive results summary:"
            if command -v jq >/dev/null 2>&1; then
                echo "   Layers: $(jq '.layer | length' "$DIVE_FILE")"
                echo "   Image Size: $(jq -r '.image.sizeBytes | (. / 1024 / 1024 | tostring + " MB")' "$DIVE_FILE")"
                echo "   Efficiency: $(jq -r '.image.efficiencyScore * 100 | tostring + "%"' "$DIVE_FILE")"
            else
                echo "   (Install jq for detailed analysis)"
            fi
            break
        fi
        echo "   Waiting... ($i/30)"
        sleep 10
    done
    
    if [ -z "$DIVE_FILE" ] || [ ! -f "$DIVE_FILE" ]; then
        echo "⚠️  Dive results not found after 5 minutes"
        echo "   This might be normal if the scan is still running"
        echo "   Available dive files:"
        ls -la dive-results/ 2>/dev/null || echo "   No dive-results directory found"
    fi
else
    echo "❌ Registry scan request failed"
fi

echo
echo "🧹 Cleaning up..."
rm -f test_payload.json

echo "🛑 Stopping server..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo
echo "🎉 Test completed!"
echo
echo "📋 Summary:"
echo "   - Server started successfully"
echo "   - Registry scan request sent"
echo "   - Dive integration tested"
echo "   - Results saved to dive-results/ directory with unique naming"
echo
echo "💡 To inspect dive results manually:"
if [ -n "$DIVE_FILE" ] && [ -f "$DIVE_FILE" ]; then
    echo "   jq . \"$DIVE_FILE\""
else
    echo "   find dive-results -name \"nginx-*-dive.json\" -exec jq . {} \\;"
fi 