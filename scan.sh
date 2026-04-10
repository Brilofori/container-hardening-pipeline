#!/bin/bash

# Container Security Scan Pipeline
# Usage: ./scan.sh <image-name> <output-prefix>
# Example: ./scan.sh debian:10 before

IMAGE=$1
PREFIX=$2
RESULTS_DIR="results"

echo "================================================"
echo " Container Security Scan"
echo " Target: $IMAGE"
echo "================================================"

# Trivy scan
echo ""
echo "[1/2] Running Trivy scan..."
trivy image $IMAGE --format json -o $RESULTS_DIR/trivy_$PREFIX.json 2>/dev/null
echo "Trivy scan complete — saved to $RESULTS_DIR/trivy_$PREFIX.json"

# Grype scan
echo ""
echo "[2/2] Running Grype scan..."
grype $IMAGE -o json --file $RESULTS_DIR/grype_$PREFIX.json 2>/dev/null
echo "Grype scan complete — saved to $RESULTS_DIR/grype_$PREFIX.json"

echo ""
echo "================================================"
echo " Scan complete. Results saved to $RESULTS_DIR/"
echo "================================================"
