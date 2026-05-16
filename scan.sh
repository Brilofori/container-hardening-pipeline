#!/bin/bash

# Container Security Scan Pipeline
# scan.sh

TARGET=$1
PREFIX=$2
RESULTS_DIR="results"

echo "================================================"
echo " Container Security Scan"
echo " Target: $TARGET"
echo "================================================"

# Step 1 — Trivy scan
echo ""
echo "[1/2] Running Trivy scan..."
sudo trivy image $TARGET --format json -o $RESULTS_DIR/trivy_$PREFIX.json 2>/dev/null
echo "Trivy scan complete — saved to $RESULTS_DIR/trivy_$PREFIX.json"

# Step 2 — Grype scan
echo ""
echo "[2/2] Running Grype scan..."
sudo grype $TARGET -o json --file $RESULTS_DIR/grype_$PREFIX.json 2>/dev/null
echo "Grype scan complete — saved to $RESULTS_DIR/grype_$PREFIX.json"

echo ""
echo "================================================"
echo " Scan complete. Results saved to $RESULTS_DIR/"
echo "================================================"
