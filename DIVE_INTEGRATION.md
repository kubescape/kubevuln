# Dive Integration for KubeVuln

This document describes the integration of dive (container image layer analysis tool) into KubeVuln.

## Overview

Dive has been integrated as a subprocess to scan container images for layer analysis after syft completes its SBOM generation. This allows KubeVuln to analyze the same image that was already pulled by syft, avoiding the need to pull the same image multiple times.

## Implementation Details

### Files Modified/Created

1. **`adapters/v1/dive.go`** - New dive adapter implementation
2. **`adapters/v1/dive_test.go`** - Tests for the dive adapter
3. **`adapters/v1/syft.go`** - Modified to include dive scanning after SBOM generation

### Key Features

- **Efficient Image Usage**: Dive scans the same image that syft has already downloaded
- **Asynchronous Execution**: Dive runs in a goroutine to avoid blocking the main SBOM generation
- **JSON Output**: Dive results are saved as JSON files in the `./dive-results/` directory
- **Unique Naming**: Each scan creates a uniquely named file to prevent overwrites
- **Timeout Support**: Configurable timeout for dive scans
- **Error Handling**: Graceful handling of dive failures without affecting SBOM generation

### Usage

The dive integration is automatically triggered when syft successfully generates an SBOM. The dive scan runs asynchronously and saves results to:

```
./dive-results/{image-name}-{timestamp}-{job-id}-dive.json
```

Where:
- `{image-name}` is the name of the scanned image
- `{timestamp}` is the scan timestamp in format `YYYYMMDD-HHMMSS`
- `{job-id}` is a unique 8-character hash based on image tag and timestamp

This ensures that multiple scans of the same image create separate files and don't overwrite previous results.

### Configuration

The dive adapter is initialized with the same timeout as the syft adapter. The dive binary path defaults to `./dive` in the current directory.

### Output Format

Dive generates JSON output with the following structure:

```json
{
  "image": {
    "sizeBytes": 123456789,
    "inefficientBytes": 12345678,
    "efficiencyScore": 0.95,
    "fileReference": [
      {
        "count": 1,
        "sizeBytes": 1024,
        "file": "/path/to/file"
      }
    ]
  },
  "layer": [
    {
      "index": 0,
      "id": "sha256:...",
      "digestId": "sha256:...",
      "sizeBytes": 1024,
      "command": "FROM alpine:latest",
      "fileList": [
        {
          "path": "/path/to/file",
          "typeFlag": 1,
          "linkName": "",
          "size": 1024,
          "fileMode": 644,
          "uid": 0,
          "gid": 0,
          "isDir": false
        }
      ]
    }
  ]
}
```

### Requirements

- Dive binary must be available in the `./dive` path or specified via configuration
- The dive binary must support the `--json` flag for JSON output

### Testing

Tests are included in `adapters/v1/dive_test.go` and will be skipped if the dive binary is not available.

### File Management

Since each scan creates a unique file, you may want to implement a cleanup strategy:

```bash
# Find all dive files for a specific image
find dive-results -name "nginx-*-dive.json"

# Find the most recent dive file for an image
find dive-results -name "nginx-*-dive.json" -type f -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-

# Clean up old dive files (keep last 10)
find dive-results -name "*-dive.json" -type f -printf '%T@ %p\n' | sort -nr | tail -n +11 | cut -d' ' -f2- | xargs rm -f
```

## Benefits

1. **No Duplicate Image Pulls**: Reuses the image already downloaded by syft
2. **Layer Analysis**: Provides detailed information about container layers
3. **Non-blocking**: Doesn't affect the main SBOM generation workflow
4. **Unique Results**: Each scan creates a separate file to preserve history
5. **Configurable**: Supports timeout and path configuration
6. **Robust**: Graceful error handling ensures main functionality isn't affected 