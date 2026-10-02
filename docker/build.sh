#!/bin/sh
# Builds with the repository root as context: the image includes
# k8s/config/radiusd.conf (the only file /.dockerignore lets through).
REPO="$(cd "$(dirname "$0")/.." && pwd)"
podman build -f "${REPO}/docker/Dockerfile" -t ghcr.io/andrewnicolalde/homelab-nac/freeradius:latest "${REPO}"
