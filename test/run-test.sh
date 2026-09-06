#!/usr/bin/env bash
# ==============================================================================
# Script: run-test.sh
# Purpose: Execute automated EAP-TLS CNSA 192-bit validation using eapol_test
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERTS_DIR="${REPO_ROOT}/certificate-authority"

# Target FreeRADIUS NodePort settings (default to Pi node IP and NodePort 31812)
RADIUS_SERVER="${1:-10.50.0.100}"
RADIUS_PORT="${2:-31812}"
RADIUS_SECRET="${3:-REPLACE_WITH_TEST_SECRET_64_CHAR}"
CONFIG_FILE="${4:-eapol_test.conf}"

IMAGE_NAME="eapol-test:local"

echo "=============================================================================="
echo "  CNSA WPA3-Enterprise 192-bit EAP-TLS Automated Test"
echo "=============================================================================="
echo "  Target Server : ${RADIUS_SERVER}:${RADIUS_PORT}"
echo "  Config File   : ${CONFIG_FILE}"
echo "  Identity      : client-device-01"
echo "=============================================================================="

# 1. Determine container runtime (podman or docker)
if command -v podman >/dev/null 2>&1; then
    CONTAINER_CLI="podman"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_CLI="docker"
else
    echo "❌ Error: Neither podman nor docker was found in your PATH." >&2
    exit 1
fi

echo "==> Using container engine: ${CONTAINER_CLI}"

# 2. Check if the eapol-test container image exists, or build it
if ! ${CONTAINER_CLI} image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    echo "==> Image '${IMAGE_NAME}' not found locally. Building from ${SCRIPT_DIR}/Dockerfile..."
    ${CONTAINER_CLI} build -t "${IMAGE_NAME}" -f "${SCRIPT_DIR}/Dockerfile" "${SCRIPT_DIR}"
    echo "✔ Successfully built ${IMAGE_NAME}"
fi

# 3. Verify that certificate files exist
for req_cert in "ca.pem" "client.crt" "client.key"; do
    if [ ! -f "${CERTS_DIR}/${req_cert}" ]; then
        echo "❌ Error: Required certificate file '${CERTS_DIR}/${req_cert}' not found." >&2
        exit 1
    fi
done

# 4. Execute eapol_test inside the container
echo "==> Running eapol_test against ${RADIUS_SERVER}:${RADIUS_PORT}..."
echo "--- [eapol_test output start] ---"

set +e
TEST_OUTPUT=$(${CONTAINER_CLI} run --rm \
    -v "${CERTS_DIR}:/certs:ro" \
    -v "${SCRIPT_DIR}:/test:ro" \
    "${IMAGE_NAME}" \
    -c "/test/${CONFIG_FILE}" \
    -a "${RADIUS_SERVER}" \
    -p "${RADIUS_PORT}" \
    -s "${RADIUS_SECRET}" \
    -M "02:00:00:00:00:01" 2>&1)
EXIT_CODE=$?
set -e

echo "${TEST_OUTPUT}"
echo "--- [eapol_test output end] ---"

# 5. Evaluate results
echo ""
echo "=============================================================================="
echo "  Test Results Summary"
echo "=============================================================================="

SUCCESS=true

# Check overall eapol_test outcome
if echo "${TEST_OUTPUT}" | grep -q "SUCCESS"; then
    echo "✔ EAP-TLS Authentication: PASSED (Handshake completed successfully)"
else
    echo "❌ EAP-TLS Authentication: FAILED"
    SUCCESS=false
fi

# Check RFC 3580 Dynamic VLAN assignment (VLAN 80)
# eapol_test prints attribute on one line and hex value on the next (0x3830 = ASCII "80")
if echo "${TEST_OUTPUT}" | grep -A 1 "Tunnel-Private-Group-Id" | grep -qiE "(3830|80)"; then
    echo "✔ Dynamic VLAN Assignment: PASSED (Assigned to VLAN 80 [hex: 3830])"
else
    echo "❌ Dynamic VLAN Assignment: FAILED (VLAN 80 attribute not received)"
    SUCCESS=false
fi

# Check Tunnel Type (VLAN / 13 -> 0x0000000d)
if echo "${TEST_OUTPUT}" | grep -A 1 "Tunnel-Type" | grep -qiE "(0000000d|13|VLAN)"; then
    echo "✔ Tunnel-Type: PASSED (VLAN [hex: 0000000d / 13])"
else
    echo "⚠️ Tunnel-Type: Attribute not detected in response"
fi

# Check Tunnel Medium Type (IEEE-802 / 6 -> 0x00000006)
if echo "${TEST_OUTPUT}" | grep -A 1 "Tunnel-Medium-Type" | grep -qiE "(00000006|IEEE-802)"; then
    echo "✔ Tunnel-Medium-Type: PASSED (IEEE-802 [hex: 00000006 / 6])"
else
    echo "⚠️ Tunnel-Medium-Type: Attribute not detected in response"
fi

echo "=============================================================================="

if [ "${SUCCESS}" = true ]; then
    echo "🎉 All EAP-TLS & CNSA Suite B 192-bit checks PASSED successfully!"
    exit 0
else
    echo "❌ Verification FAILED. Please review the server and client output above."
    exit 1
fi
