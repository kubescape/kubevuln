# KubeVuln Dive Integration Test Guide

This guide shows how to test the dive integration by building the KubeVuln binary and sending curl requests to verify that dive reports are being generated.

## Prerequisites

1. **Dive Binary**: Ensure the `dive` binary is present in the project root directory
2. **Go Environment**: Make sure Go is installed and configured
3. **Network Access**: The server needs internet access to pull Docker images

## Step 1: Build the KubeVuln Binary

```bash
# Build the binary
go build -o kubevuln ./cmd/http/

# Verify the binary was created
ls -la kubevuln
```

## Step 2: Start the KubeVuln Server

```bash
# Start the server in the background
./kubevuln &

# Wait for server to start (usually 5-10 seconds)
sleep 5

# Test if server is ready
curl -s http://localhost:8080/v1/readiness
```

Expected output:
```json
{"status":200,"title":"OK"}
```

## Step 3: Test the Dive Integration

### Method 1: Registry Scan (Recommended)

This endpoint triggers both SBOM generation and dive analysis:

```bash
curl -s -X POST http://localhost:8080/v1/scanRegistryImage \
  -H "Content-Type: application/json" \
  -d '{
    "session": {
      "jobIDs": ["test-123"],
      "timestamp": "2024-01-01T00:00:00Z",
      "rootJobID": "test-123",
      "action": "vulnerability-scan"
    },
    "imageTag": "nginx:latest",
    "wlid": "wlid://cluster-test/namespace-default/deployment-nginx",
    "isScanned": false,
    "containerName": "nginx",
    "jobID": "test-123",
    "parentJobID": "test-123",
    "actionIDN": 1
  }'
```

Expected response:
```json
{"detail":"ImageTag=nginx:latest","status":200,"title":"OK"}
```

### Method 2: SBOM Generation

This endpoint only generates SBOM (dive will still run):

```bash
curl -s -X POST http://localhost:8080/v1/generateSBOM \
  -H "Content-Type: application/json" \
  -d '{
    "session": {
      "jobIDs": ["test-123"],
      "timestamp": "2024-01-01T00:00:00Z",
      "rootJobID": "test-123",
      "action": "vulnerability-scan"
    },
    "imageTag": "nginx:latest",
    "wlid": "wlid://cluster-test/namespace-default/deployment-nginx",
    "isScanned": false,
    "containerName": "nginx",
    "jobID": "test-123",
    "parentJobID": "test-123",
    "actionIDN": 1
  }'
```

## Step 4: Monitor for Dive Results

After sending the request, wait for dive to complete and check for results:

```bash
# Wait for dive to complete (usually 1-3 minutes)
sleep 60

# Check if dive results were created
ls -la dive-results/

# Expected output:
# -rw-r--r-- 1 user user 1493335 Jun 18 13:32 nginx-latest-nohash-dive.json
```

## Step 5: Analyze Dive Results

### Basic Analysis

```bash
# Check file size
du -h dive-results/nginx-latest-nohash-dive.json

# Basic dive summary
jq '.image | {size: .sizeBytes, efficiency: .efficiencyScore, inefficient: .inefficientBytes}' dive-results/nginx-latest-nohash-dive.json
```

Expected output:
```json
{
  "size": 192436529,
  "efficiency": 0.9900102126660162,
  "inefficient": 3568758
}
```

### Detailed Analysis

```bash
# Number of layers
jq '.layer | length' dive-results/nginx-latest-nohash-dive.json

# Layer details
jq '.layer[] | {index: .index, size: .sizeBytes, command: .command}' dive-results/nginx-latest-nohash-dive.json

# Efficiency score as percentage
jq -r '.image.efficiencyScore * 100 | tostring + "%"' dive-results/nginx-latest-nohash-dive.json
```

## Step 6: Test with Different Images

You can test with any Docker image:

```bash
# Test with alpine
curl -s -X POST http://localhost:8080/v1/scanRegistryImage \
  -H "Content-Type: application/json" \
  -d '{
    "session": {"jobIDs": ["test-456"], "timestamp": "2024-01-01T00:00:00Z", "rootJobID": "test-456", "action": "vulnerability-scan"},
    "imageTag": "alpine:latest",
    "wlid": "wlid://cluster-test/namespace-default/deployment-alpine",
    "isScanned": false,
    "containerName": "alpine",
    "jobID": "test-456",
    "parentJobID": "test-456",
    "actionIDN": 1
  }'

# Test with ubuntu
curl -s -X POST http://localhost:8080/v1/scanRegistryImage \
  -H "Content-Type: application/json" \
  -d '{
    "session": {"jobIDs": ["test-789"], "timestamp": "2024-01-01T00:00:00Z", "rootJobID": "test-789", "action": "vulnerability-scan"},
    "imageTag": "ubuntu:latest",
    "wlid": "wlid://cluster-test/namespace-default/deployment-ubuntu",
    "isScanned": false,
    "containerName": "ubuntu",
    "jobID": "test-789",
    "parentJobID": "test-789",
    "actionIDN": 1
  }'
```

## Step 7: Clean Up

```bash
# Stop the server
pkill -f kubevuln

# Clean up dive results (optional)
rm -rf dive-results/
```

## Available API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/readiness` | GET | Check if server is ready |
| `/v1/liveness` | GET | Check if server is alive |
| `/v1/scanRegistryImage` | POST | Scan image from registry (triggers dive) |
| `/v1/generateSBOM` | POST | Generate SBOM (triggers dive) |
| `/v1/scanImage` | POST | Scan container image |
| `/v1/scanApplicationProfile` | POST | Scan application profile |

## Troubleshooting

### Server Won't Start
- Check if port 8080 is available
- Ensure dive binary is present: `ls -la dive`
- Check logs: `./kubevuln` (run without background)

### No Dive Results
- Wait longer (dive can take 1-3 minutes)
- Check if dive binary is executable: `chmod +x dive`
- Verify dive works manually: `./dive nginx:latest --json test.json`

### Network Issues
- Ensure internet access for pulling Docker images
- Check firewall settings
- Try with a different image tag

## Expected Behavior

1. **Server starts** and responds to readiness checks
2. **API requests are accepted** with 200 status codes
3. **Dive results are generated** in `dive-results/` directory
4. **File naming pattern**: `{image-name}-dive.json`
5. **JSON structure** includes image metrics and layer details
6. **Asynchronous execution** - dive runs in background without blocking API responses

## Verification Checklist

- [ ] KubeVuln binary builds successfully
- [ ] Server starts and responds to readiness checks
- [ ] API requests return 200 status codes
- [ ] Dive results are created in `dive-results/` directory
- [ ] JSON files contain valid dive analysis data
- [ ] Multiple images can be scanned successfully
- [ ] Server can be stopped cleanly

## Performance Notes

- **First scan**: May take 2-3 minutes (image download + analysis)
- **Subsequent scans**: Faster if image is cached
- **Dive execution**: Runs asynchronously, doesn't block API responses
- **File sizes**: Dive results typically 1-2MB per image 