#!/usr/bin/env bash
# ==============================================================================
# Setup GHCR Image Pull Secret for Kubernetes
# ==============================================================================
# Creates or updates the 'ghcr-auth' secret in 'freeradius-experimentation'
# namespace so the cluster can pull private images from GitHub Container Registry.
#
# Usage:
#   ./setup-ghcr-auth.sh
# ==============================================================================

set -euo pipefail

NAMESPACE="freeradius-experimentation"
SECRET_NAME="ghcr-auth"
REGISTRY="ghcr.io"
GITHUB_USER="${GITHUB_USER:-andrewnicolalde}"

# Always prompt for token securely via masked input
read -rsp "Enter your GitHub Classic PAT (with 'read:packages' scope): " GITHUB_PAT
echo ""

if [ -z "${GITHUB_PAT}" ]; then
    echo "Error: GitHub PAT cannot be empty." >&2
    exit 1
fi

echo "==> Ensuring namespace '${NAMESPACE}' exists..."
kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || kubectl apply -f 00-namespace.yaml

echo "==> Creating or updating '${SECRET_NAME}' secret in '${NAMESPACE}'..."
# Using --dry-run=client piped to kubectl apply makes this operation completely idempotent
kubectl -n "${NAMESPACE}" create secret docker-registry "${SECRET_NAME}" \
    --docker-server="${REGISTRY}" \
    --docker-username="${GITHUB_USER}" \
    --docker-password="${GITHUB_PAT}" \
    --dry-run=client -o yaml | kubectl apply -f -

echo "✔ Successfully configured '${SECRET_NAME}' in namespace '${NAMESPACE}'."
