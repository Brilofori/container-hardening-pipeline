#!/bin/bash

# Container Security & Automated Hardening Pipeline
# Usage: ./pipeline.sh <target-image>
# Example: ./pipeline.sh debian:10

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: ./pipeline.sh <target-image>"
    exit 1
fi

echo ""
echo "================================================"
echo " CONTAINER HARDENING PIPELINE"
echo " Target: $TARGET"
echo "================================================"

# Step 1 — Before scan
echo ""
echo "[1/5] Scanning original image..."
./scan.sh $TARGET before

# Step 2 — Apply hardening
echo ""
echo "[2/5] Applying hardening fixes..."
python3 harden.py results/trivy_before.json Dockerfile

# Step 3 — Build hardened image
echo ""
echo "[3/5] Building hardened image..."
sudo docker build -f Dockerfile.hardened -t vulnerable-app:after .

# Step 4 — After scan
echo ""
echo "[4/5] Scanning hardened image..."
./scan.sh vulnerable-app:after after

# Step 5 — Summary
echo ""
echo "[5/5] Generating before and after summary..."
python3 summarise.py results/trivy_before.json results/trivy_after.json results/grype_before.json results/grype_after.json
# Standards verification on hardened image
echo ""
echo "Verifying standards compliance on hardened image..."
echo '{"Results": []}' > results/trivy_after_empty.json
python3 harden.py results/trivy_after_empty.json Dockerfile.hardened

echo ""
echo "================================================"
echo " PIPELINE COMPLETE"
echo " Check results/ folder for full scan output"
echo "================================================"
