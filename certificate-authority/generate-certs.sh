#!/usr/bin/env bash
# ==============================================================================
# Certificate Generation Script for 802.1X / EAP-TLS using Smallstep CLI (`step`)
# Configured for WPA3-Enterprise 192-bit (CNSA / Suite B) Mode (NIST P-384 / SHA-384)
# ==============================================================================
# Supports two modes of operation:
#   1. Software Mode (Default):
#      - Mints a software Root CA (root_ca.crt / root_ca.key) on disk.
#      - Signs server, client, and authenticator leaf certificates via software key.
#   2. Hardware Root of Trust Mode (--yubikey or USE_YUBIKEY=true):
#      - Operates with 3 distinct Root CAs residing on a single YubiKey 5:
#          * Slot 9c: RADIUS Server Root CA (server_root_ca.crt)
#          * Slot 9d: User Endpoints Root CA (user_root_ca.crt / ca.pem)
#          * Slot 82: UniFi Infrastructure Root CA (unifi_root_ca.crt)
#      - Prompts for PIV PIN interactively into process memory; never writes PIN to disk.
#      - Zero disk exposure for Root CA private keys; physical touch enforced.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ------------------------------------------------------------------------------
# 1. Configuration & Argument Parsing
# ------------------------------------------------------------------------------
# Source optional certs.env configuration file if present
if [ -f "${SCRIPT_DIR}/certs.env" ]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/certs.env"
elif [ -f "${SCRIPT_DIR}/../certs.env" ]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/../certs.env"
elif [ -f "${SCRIPT_DIR}/../../homelab-networking-config/certs.env" ]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/../../homelab-networking-config/certs.env"
elif [ -f "${SCRIPT_DIR}/../../homelab-config/certs.env" ]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/../../homelab-config/certs.env"
fi

USE_YUBIKEY="${USE_YUBIKEY:-false}"
if [ "${1:-}" = "--yubikey" ]; then
    USE_YUBIKEY="true"
    shift
fi

RADIUS_IP="${1:-${RADIUS_IP:-10.50.0.100}}"
CLIENT_IDENTITY="${2:-${CLIENT_IDENTITY:-client-device-01}}"
ROOT_CA_NAME="${ROOT_CA_NAME:-Enterprise Root CA}"
AP_IDENTITY="${AP_IDENTITY:-unifi-aps}"
CURVE="${CURVE:-P-384}"

# PIV Slot mappings for YubiKey 3-CA architecture
SLOT_SERVER_CA="${SLOT_SERVER_CA:-9c}"
SLOT_USER_CA="${SLOT_USER_CA:-9d}"
SLOT_UNIFI_CA="${SLOT_UNIFI_CA:-82}"

# Determine output directory
OUTPUT_DIR="${OUTPUT_DIR:-${PWD}}"
mkdir -p "${OUTPUT_DIR}"
cd "${OUTPUT_DIR}"

echo "=============================================================================="
echo "  CNSA 192-bit Certificate Generation (step CLI)"
echo "=============================================================================="
echo "  Mode            : $([ "${USE_YUBIKEY}" = "true" ] && echo "YubiKey Hardware Root of Trust (3-CA)" || echo "Software Root CA (Disk-backed)")"
echo "  Output Dir      : ${OUTPUT_DIR}"
echo "  RADIUS Server IP: ${RADIUS_IP}"
echo "  Client Identity : ${CLIENT_IDENTITY}"
echo "  Root CA Name    : ${ROOT_CA_NAME}"
echo "  Elliptic Curve  : ${CURVE} (ECDSA-SHA384)"
echo "=============================================================================="

# Optional additional Subject Alternative Names (SANs)
if [ -z "${ADDITIONAL_SANS+x}" ]; then
    ADDITIONAL_SANS=()
fi

SERVER_SAN_ARGS=(--san "${RADIUS_IP}")
if [ "${#ADDITIONAL_SANS[@]}" -gt 0 ]; then
    for san in "${ADDITIONAL_SANS[@]}"; do
        SERVER_SAN_ARGS+=(--san "${san}")
    done
fi

# ------------------------------------------------------------------------------
# 2. Execution Mode Selection
# ------------------------------------------------------------------------------
if [ "${USE_YUBIKEY}" = "true" ]; then
    # Ensure step-kms-plugin is available in PATH
    if [ -d "${HOME}/go/bin" ] && [[ ":$PATH:" != *":${HOME}/go/bin:"* ]]; then
        export PATH="${HOME}/go/bin:${PATH}"
    fi

    if ! command -v step-kms-plugin >/dev/null 2>&1; then
        echo "❌ Error: 'step-kms-plugin' was not found in PATH." >&2
        echo "   Please ensure step-kms-plugin is installed in ~/go/bin or /usr/local/bin." >&2
        exit 1
    fi

    # Securely capture PIN into process memory (never persisted to disk)
    if [ -z "${YUBIKEY_PIN:-}" ]; then
        echo ""
        read -s -r -p "Enter YubiKey PIV PIN: " YUBIKEY_PIN
        echo ""
    fi
    trap 'unset YUBIKEY_PIN' EXIT INT TERM

    KEY_URI_SERVER="yubikey:slot-id=${SLOT_SERVER_CA}?pin-value=${YUBIKEY_PIN}"
    KEY_URI_USER="yubikey:slot-id=${SLOT_USER_CA}?pin-value=${YUBIKEY_PIN}"
    KEY_URI_UNIFI="yubikey:slot-id=${SLOT_UNIFI_CA}?pin-value=${YUBIKEY_PIN}"

    # --------------------------------------------------------------------------
    # YubiKey CA 1: RADIUS Server Root CA (Slot 9c) & Server Leaf Cert
    # --------------------------------------------------------------------------
    echo ""
    echo "--- [1/3] RADIUS Server PKI (Slot ${SLOT_SERVER_CA}) ---"
    if [ ! -f "server_root_ca.crt" ]; then
        echo "==> Minting RADIUS Server Root CA via YubiKey Slot ${SLOT_SERVER_CA}..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${ROOT_CA_NAME} - RADIUS Server" server_root_ca.crt \
            --profile root-ca \
            --key "${KEY_URI_SERVER}" \
            --not-after=87600h
        echo "✔ Created: server_root_ca.crt"
    else
        echo "==> server_root_ca.crt already exists. Skipping."
    fi

    if [ ! -f "server.crt" ]; then
        echo "==> Creating FreeRADIUS Server Certificate for ${RADIUS_IP}..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${RADIUS_IP}" server.crt server.key \
            --profile leaf \
            --ca server_root_ca.crt \
            --ca-key "${KEY_URI_SERVER}" \
            --kty EC --curve "${CURVE}" \
            "${SERVER_SAN_ARGS[@]}" \
            --not-after=8760h \
            --no-password --insecure
        echo "✔ Created: server.crt, server.key"
    else
        echo "==> server.crt already exists. Skipping."
    fi

    if [ ! -f "server.pem" ] && [ -f "server.crt" ] && [ -f "server.key" ]; then
        cat server.crt server.key > server.pem
        chmod 600 server.pem
        echo "✔ Created combined server.pem for Alpine FreeRADIUS"
    fi

    # --------------------------------------------------------------------------
    # YubiKey CA 2: User Endpoints Root CA (Slot 9d) & Client Leaf Cert
    # --------------------------------------------------------------------------
    echo ""
    echo "--- [2/3] User Endpoints PKI (Slot ${SLOT_USER_CA}) ---"
    if [ ! -f "user_root_ca.crt" ]; then
        echo "==> Minting User Endpoints Root CA via YubiKey Slot ${SLOT_USER_CA}..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${ROOT_CA_NAME} - User Endpoints" user_root_ca.crt \
            --profile root-ca \
            --key "${KEY_URI_USER}" \
            --not-after=87600h
        echo "✔ Created: user_root_ca.crt"
    else
        echo "==> user_root_ca.crt already exists. Skipping."
    fi

    # ca.pem is mounted into FreeRADIUS eap module to validate connecting users
    if [ ! -f "ca.pem" ] && [ -f "user_root_ca.crt" ]; then
        cp user_root_ca.crt ca.pem
        echo "✔ Created ca.pem from user_root_ca.crt for FreeRADIUS EAP-TLS client validation"
    fi
    if [ ! -f "ca.crt" ] && [ -f "user_root_ca.crt" ]; then
        cp user_root_ca.crt ca.crt
        echo "✔ Created ca.crt from user_root_ca.crt"
    fi
    if [ ! -f "root_ca.crt" ] && [ -f "user_root_ca.crt" ]; then
        cp user_root_ca.crt root_ca.crt
        echo "✔ Created root_ca.crt compatibility alias from user_root_ca.crt"
    fi

    if [ ! -f "client.crt" ]; then
        echo "==> Creating Client Certificate (${CLIENT_IDENTITY})..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${CLIENT_IDENTITY}" client.crt client.key \
            --profile leaf \
            --ca user_root_ca.crt \
            --ca-key "${KEY_URI_USER}" \
            --kty EC --curve "${CURVE}" \
            --not-after=8760h \
            --no-password --insecure
        echo "✔ Created: client.crt, client.key"
    else
        echo "==> client.crt already exists. Skipping."
    fi

    # --------------------------------------------------------------------------
    # YubiKey CA 3: UniFi Infrastructure Root CA (Slot 82) & AP Authenticator Cert
    # --------------------------------------------------------------------------
    echo ""
    echo "--- [3/3] UniFi Infrastructure PKI (Slot ${SLOT_UNIFI_CA}) ---"
    if [ ! -f "unifi_root_ca.crt" ]; then
        echo "==> Minting UniFi Infrastructure Root CA via YubiKey Slot ${SLOT_UNIFI_CA}..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${ROOT_CA_NAME} - UniFi Infrastructure" unifi_root_ca.crt \
            --profile root-ca \
            --key "${KEY_URI_UNIFI}" \
            --not-after=87600h
        echo "✔ Created: unifi_root_ca.crt"
    else
        echo "==> unifi_root_ca.crt already exists. Skipping."
    fi

    if [ ! -f "unifi-ap.crt" ]; then
        echo "==> Creating UniFi AP Authenticator Certificate..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${AP_IDENTITY}" unifi-ap.crt unifi-ap.key \
            --profile leaf \
            --ca unifi_root_ca.crt \
            --ca-key "${KEY_URI_UNIFI}" \
            --kty EC --curve "${CURVE}" \
            --not-after=8760h \
            --no-password --insecure
        echo "✔ Created: unifi-ap.crt, unifi-ap.key"
    else
        echo "==> unifi-ap.crt already exists. Skipping."
    fi

    # --------------------------------------------------------------------------
    # Packaging Client PKCS#12 Bundle (Dual Root Trust Anchor)
    # --------------------------------------------------------------------------
    echo ""
    if [ ! -f "client.p12" ]; then
        echo "==> Packaging client certificate into client.p12..."
        # Bundles user_root_ca.crt (client identity chain) and server_root_ca.crt (server validation)
        step certificate p12 client.p12 client.crt client.key \
            --ca user_root_ca.crt \
            --ca server_root_ca.crt
        echo "✔ Created: client.p12"
    else
        echo "==> client.p12 already exists. Skipping."
    fi

    echo ""
    echo "=============================================================================="
    echo "All YubiKey-backed certificates successfully generated in ${OUTPUT_DIR}:"
    echo "  - server_root_ca.crt          : Server Root CA (Public anchor for clients)"
    echo "  - server.crt / server.pem     : FreeRADIUS Server Cert (signed by Slot ${SLOT_SERVER_CA})"
    echo "  - user_root_ca.crt / ca.pem   : User Endpoints Root CA (Mounted into FreeRADIUS)"
    echo "  - client.crt / client.key     : Client Supplicant Cert (signed by Slot ${SLOT_USER_CA})"
    echo "  - unifi_root_ca.crt           : UniFi Infrastructure Root CA (for RADSec)"
    echo "  - unifi-ap.crt / unifi-ap.key : UniFi AP Authenticator Cert (signed by Slot ${SLOT_UNIFI_CA})"
    echo "  - client.p12                  : Client PKCS#12 bundle (contains client cert + CAs)"
    echo "=============================================================================="

else
    # --------------------------------------------------------------------------
    # Software Mode (Standard disk-based Root CA)
    # --------------------------------------------------------------------------
    if [ ! -f "root_ca.crt" ]; then
        echo "==> Creating Software Root CA (${CURVE})..."
        step certificate create "${ROOT_CA_NAME}" root_ca.crt root_ca.key \
            --profile root-ca \
            --kty EC --curve "${CURVE}" \
            --not-after=87600h \
            --no-password --insecure
        echo "✔ Root CA created: root_ca.crt, root_ca.key"
    else
        echo "==> Root CA already exists (root_ca.crt). Skipping."
    fi

    if [ ! -f "server.crt" ]; then
        echo "==> Creating FreeRADIUS Server Certificate for ${RADIUS_IP}..."
        step certificate create "${RADIUS_IP}" server.crt server.key \
            --profile leaf \
            --ca root_ca.crt \
            --ca-key root_ca.key \
            --kty EC --curve "${CURVE}" \
            "${SERVER_SAN_ARGS[@]}" \
            --not-after=8760h \
            --no-password --insecure
        echo "✔ Server cert created: server.crt, server.key"
    else
        echo "==> Server certificate already exists (server.crt). Skipping."
    fi

    if [ ! -f "server.pem" ] && [ -f "server.crt" ] && [ -f "server.key" ]; then
        cat server.crt server.key > server.pem
        chmod 600 server.pem
        echo "✔ Created combined server.pem for Alpine FreeRADIUS"
    fi
    if [ ! -f "ca.pem" ] && [ -f "root_ca.crt" ]; then
        cp root_ca.crt ca.pem
        echo "✔ Created ca.pem from root_ca.crt"
    fi

    if [ ! -f "unifi-ap.crt" ]; then
        echo "==> Creating UniFi AP Authenticator Certificate..."
        step certificate create "${AP_IDENTITY}" unifi-ap.crt unifi-ap.key \
            --profile leaf \
            --ca root_ca.crt \
            --ca-key root_ca.key \
            --kty EC --curve "${CURVE}" \
            --not-after=8760h \
            --no-password --insecure
        echo "✔ UniFi AP cert created: unifi-ap.crt, unifi-ap.key"
    else
        echo "==> UniFi AP certificate already exists (unifi-ap.crt). Skipping."
    fi

    if [ ! -f "client.crt" ]; then
        echo "==> Creating Client Certificate (${CLIENT_IDENTITY})..."
        step certificate create "${CLIENT_IDENTITY}" client.crt client.key \
            --profile leaf \
            --ca root_ca.crt \
            --ca-key root_ca.key \
            --kty EC --curve "${CURVE}" \
            --not-after=8760h \
            --no-password --insecure
        echo "✔ Client cert created: client.crt, client.key"
    else
        echo "==> Client certificate already exists (client.crt). Skipping."
    fi

    if [ ! -f "client.p12" ]; then
        echo "==> Packaging client certificate into client.p12..."
        step certificate p12 client.p12 client.crt client.key \
            --ca root_ca.crt
        echo "✔ PKCS#12 bundle created: client.p12"
    else
        echo "==> Client PKCS#12 bundle already exists (client.p12). Skipping."
    fi

    echo ""
    echo "=============================================================================="
    echo "All certificates successfully generated in ${OUTPUT_DIR}:"
    echo "  - root_ca.crt / root_ca.key   : Root Certificate Authority"
    echo "  - server.crt / server.key     : FreeRADIUS Server Certificate"
    echo "  - unifi-ap.crt / unifi-ap.key : UniFi AP Authenticator Client Cert"
    echo "  - client.crt / client.key     : End-user Client Identity Cert"
    echo "  - client.p12                  : PKCS#12 bundle for client import"
    echo "=============================================================================="
fi
