#!/bin/bash

echo "=== Running KubeVuln in Local Mode ==="
echo

# Create config directory structure
mkdir -p /tmp/kubevuln-config

# Copy config file
cp config.json /tmp/kubevuln-config/clusterData.json

echo "📁 Configuration:"
echo "   - keepLocal: true (no external API calls)"
echo "   - storage: false (no persistent storage)"
echo "   - Config directory: /tmp/kubevuln-config"
echo

# Set environment variable to use our config directory
export CONFIG_DIR=/tmp/kubevuln-config

echo "🚀 Starting KubeVuln in local mode..."
echo "   This will avoid external API calls and run everything locally"
echo

# Start the server
./kubevuln 