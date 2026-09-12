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
#
# Execution Modes (One Required):
#   --full-with-defaults : Bootstrap full infrastructure (Server, AP, default client)
#   --client <identity>  : Onboard an individual client device (<identity>.crt/.key/.p12)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_usage() {
    cat <<EOF
==============================================================================
Certificate Generation Script for 802.1X / EAP-TLS (CNSA P-384)
==============================================================================

Usage:
  $(basename "$0") --full-with-defaults [options]
  $(basename "$0") --client <identity> [options]

Modes (one required):
  --full-with-defaults    Generate complete infrastructure suite (Server PKI,
                          UniFi AP PKI, and default workstation client)
  --client <identity>     Generate credentials exclusively for a specific client
                          device (<identity>.crt, <identity>.key, <identity>.p12)

Options:
  --config, -c <file>     Path to environment configuration file (e.g. certs.env)
  --output-dir, -o <dir>  Target directory for generated certificates (default: cwd)
  --yubikey               Use YubiKey hardware root of trust (3-CA architecture)
  --force, -f             Overwrite existing certificates/keys if already present
  --help, -h              Display this help message

Examples:
  # Bootstrap initial homelab PKI
  ./generate-certs.sh --full-with-defaults

  # Provision a new client device
  ./generate-certs.sh --client client-device-02

  # Force re-issuance of a specific client credential
  ./generate-certs.sh --client client-device-02 --force
==============================================================================
EOF
}

# ------------------------------------------------------------------------------
# 1. Configuration & Argument Parsing
# ------------------------------------------------------------------------------
RUN_MODE=""
TARGET_CLIENT=""
FORCE="false"
CONFIG_FILE="${CONFIG_FILE:-${CERTS_ENV:-}}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
USE_YUBIKEY="${USE_YUBIKEY:-false}"

POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --full-with-defaults)
            RUN_MODE="full"
            shift
            ;;
        --client)
            if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
                echo "❌ Error: --client requires a valid client identity name." >&2
                echo "   Example: $0 --client client-device-02" >&2
                exit 1
            fi
            RUN_MODE="client"
            TARGET_CLIENT="$2"
            shift 2
            ;;
        --force|-f)
            FORCE="true"
            shift
            ;;
        --config|-c)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --output-dir|-o)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --yubikey)
            USE_YUBIKEY="true"
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# Restore positional parameters
set -- "${POSITIONAL_ARGS[@]:+${POSITIONAL_ARGS[@]}}"

# Enforce explicit execution mode
if [ -z "${RUN_MODE}" ]; then
    echo "❌ Error: No execution mode specified." >&2
    echo "   You must specify either --full-with-defaults or --client <identity>." >&2
    echo "" >&2
    show_usage >&2
    exit 1
fi

# Source optional configuration file if specified or present locally
if [ -n "${CONFIG_FILE}" ] && [ -f "${CONFIG_FILE}" ]; then
    # shellcheck source=/dev/null
    source "${CONFIG_FILE}"
elif [ -f "./certs.env" ]; then
    # shellcheck source=/dev/null
    source "./certs.env"
elif [ -f "${SCRIPT_DIR}/certs.env" ]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/certs.env"
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
if [ "${RUN_MODE}" = "full" ]; then
echo "  Action          : Full Infrastructure Bootstrap (--full-with-defaults)"
echo "  RADIUS Server IP: ${RADIUS_IP}"
echo "  Default Client  : ${CLIENT_IDENTITY}"
else
echo "  Action          : Client Device Onboarding (--client)"
echo "  Client Identity : ${TARGET_CLIENT}"
fi
echo "  Output Dir      : ${OUTPUT_DIR}"
echo "  Root CA Name    : ${ROOT_CA_NAME}"
echo "  Elliptic Curve  : ${CURVE} (ECDSA-SHA384)"
echo "  Force Overwrite : ${FORCE}"
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

FORCE_ARG=()
P12_FORCE_ARG=()
if [ "${FORCE}" = "true" ]; then
    FORCE_ARG=(--force)
    P12_FORCE_ARG=(-f)
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

    # ==========================================================================
    # BRANCH A: Client Device Onboarding Mode (--client <identity>)
    # ==========================================================================
    if [ "${RUN_MODE}" = "client" ]; then
        echo ""
        echo "--- User Endpoints PKI (Slot ${SLOT_USER_CA}) ---"

        # Ensure User Endpoints Root CA exists in output dir
        if [ ! -f "user_root_ca.crt" ]; then
            echo "==> Minting User Endpoints Root CA via YubiKey Slot ${SLOT_USER_CA}..."
            echo "    >>> Touch your YubiKey when LED flashes <<<"
            step certificate create "${ROOT_CA_NAME} - User Endpoints" user_root_ca.crt \
                --profile root-ca \
                --key "${KEY_URI_USER}" \
                --not-after=87600h \
                "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
            echo "✔ Created: user_root_ca.crt"
        else
            echo "==> user_root_ca.crt already exists. Skipping."
        fi

        if [ ! -f "ca.pem" ] && [ -f "user_root_ca.crt" ]; then
            cp user_root_ca.crt ca.pem
            echo "✔ Created ca.pem from user_root_ca.crt for FreeRADIUS EAP-TLS client validation"
        fi

        CLIENT_CRT="${TARGET_CLIENT}.crt"
        CLIENT_KEY="${TARGET_CLIENT}.key"
        CLIENT_P12="${TARGET_CLIENT}.p12"

        if [ -f "${CLIENT_CRT}" ] && [ "${FORCE}" != "true" ]; then
            echo "==> ${CLIENT_CRT} already exists. Skipping (use --force to overwrite)."
        else
            echo "==> Creating Client Certificate (${TARGET_CLIENT})..."
            echo "    >>> Touch your YubiKey when LED flashes <<<"
            step certificate create "${TARGET_CLIENT}" "${CLIENT_CRT}" "${CLIENT_KEY}" \
                --profile leaf \
                --ca user_root_ca.crt \
                --ca-key "${KEY_URI_USER}" \
                --kty EC --curve "${CURVE}" \
                --not-after=8760h \
                --no-password --insecure \
                "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
            echo "✔ Created: ${CLIENT_CRT}, ${CLIENT_KEY}"
        fi

        if [ -f "${CLIENT_P12}" ] && [ "${FORCE}" != "true" ]; then
            echo "==> ${CLIENT_P12} already exists. Skipping (use --force to overwrite)."
        else
            echo ""
            echo "==> Packaging client certificate into ${CLIENT_P12}..."
            CA_ARGS=(--ca user_root_ca.crt)
            if [ -f "server_root_ca.crt" ]; then
                CA_ARGS+=(--ca server_root_ca.crt)
            fi
            # NOTE (macOS / Apple Keychain Compatibility vs. Modern Defaults):
            # By default, `step certificate p12` encodes archives using modern PBES2 (RFC 8018)
            # with AES-256-CBC, PBKDF2 (HMAC-SHA256), and a SHA-256 MAC for integrity.
            # This modern default is cryptographically superior: it provides full 256-bit symmetric
            # security and robust offline GPU brute-force resistance, avoiding deprecated 3DES
            # (~112-bit effective security) and export-grade 40-bit RC2.
            #
            # However, Apple's Security.framework (SecPKCS12Import) has a hard OS-level limitation:
            # it strictly expects legacy PKCS#12 v1.0 (RFC 7292) structures using SHA-1 MAC and
            # PBES1 (3DES for keys, RC2-40 for cert bags). When fed modern PBES2, Apple Keychain
            # fails with "unable to decode the provided data" (SecKeychainItemImport: MAC verification failed).
            # We pass `--legacy` here strictly to ensure compatibility with Apple's Keychain parser.
            step certificate p12 "${CLIENT_P12}" "${CLIENT_CRT}" "${CLIENT_KEY}" \
                --legacy \
                "${CA_ARGS[@]:+${CA_ARGS[@]}}" \
                "${P12_FORCE_ARG[@]:+${P12_FORCE_ARG[@]}}"
            chmod 600 "${CLIENT_P12}"
            echo "✔ Created: ${CLIENT_P12}"
        fi

        echo ""
        echo "=============================================================================="
        echo "Client credentials successfully provisioned in ${OUTPUT_DIR}:"
        echo "  - Certificate : ${CLIENT_CRT}"
        echo "  - Private Key : ${CLIENT_KEY}"
        echo "  - PKCS#12     : ${CLIENT_P12}"
        echo "=============================================================================="
        exit 0
    fi

    # ==========================================================================
    # BRANCH B: Full Infrastructure Bootstrap Mode (--full-with-defaults)
    # ==========================================================================
    # --------------------------------------------------------------------------
    # YubiKey CA 1: RADIUS Server Root CA (Slot 9c) & Server Leaf Cert
    # --------------------------------------------------------------------------
    echo ""
    echo "--- [1/3] RADIUS Server PKI (Slot ${SLOT_SERVER_CA}) ---"
    if [ ! -f "server_root_ca.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Minting RADIUS Server Root CA via YubiKey Slot ${SLOT_SERVER_CA}..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${ROOT_CA_NAME} - RADIUS Server" server_root_ca.crt \
            --profile root-ca \
            --key "${KEY_URI_SERVER}" \
            --not-after=87600h \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Created: server_root_ca.crt"
    else
        echo "==> server_root_ca.crt already exists. Skipping."
    fi

    if [ ! -f "server.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Creating FreeRADIUS Server Certificate for ${RADIUS_IP}..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${RADIUS_IP}" server.crt server.key \
            --profile leaf \
            --ca server_root_ca.crt \
            --ca-key "${KEY_URI_SERVER}" \
            --kty EC --curve "${CURVE}" \
            "${SERVER_SAN_ARGS[@]:+${SERVER_SAN_ARGS[@]}}" \
            --not-after=8760h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Created: server.crt, server.key"
    else
        echo "==> server.crt already exists. Skipping."
    fi

    if [ -f "server.crt" ] && [ -f "server.key" ]; then
        cat server.crt server.key > server.pem
        chmod 600 server.pem
        echo "✔ Created combined server.pem for Alpine FreeRADIUS"
    fi

    # --------------------------------------------------------------------------
    # YubiKey CA 2: User Endpoints Root CA (Slot 9d) & Client Leaf Cert
    # --------------------------------------------------------------------------
    echo ""
    echo "--- [2/3] User Endpoints PKI (Slot ${SLOT_USER_CA}) ---"
    if [ ! -f "user_root_ca.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Minting User Endpoints Root CA via YubiKey Slot ${SLOT_USER_CA}..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${ROOT_CA_NAME} - User Endpoints" user_root_ca.crt \
            --profile root-ca \
            --key "${KEY_URI_USER}" \
            --not-after=87600h \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Created: user_root_ca.crt"
    else
        echo "==> user_root_ca.crt already exists. Skipping."
    fi

    # ca.pem is mounted into FreeRADIUS eap module to validate connecting users
    if [ -f "user_root_ca.crt" ]; then
        cp user_root_ca.crt ca.pem
        echo "✔ Created ca.pem from user_root_ca.crt for FreeRADIUS EAP-TLS client validation"
        cp user_root_ca.crt ca.crt
        echo "✔ Created ca.crt from user_root_ca.crt"
        cp user_root_ca.crt root_ca.crt
        echo "✔ Created root_ca.crt compatibility alias from user_root_ca.crt"
    fi

    if [ ! -f "client.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Creating Client Certificate (${CLIENT_IDENTITY})..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${CLIENT_IDENTITY}" client.crt client.key \
            --profile leaf \
            --ca user_root_ca.crt \
            --ca-key "${KEY_URI_USER}" \
            --kty EC --curve "${CURVE}" \
            --not-after=8760h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Created: client.crt, client.key"
    else
        echo "==> client.crt already exists. Skipping."
    fi

    # --------------------------------------------------------------------------
    # YubiKey CA 3: UniFi Infrastructure Root CA (Slot 82) & AP Authenticator Cert
    # --------------------------------------------------------------------------
    echo ""
    echo "--- [3/3] UniFi Infrastructure PKI (Slot ${SLOT_UNIFI_CA}) ---"
    if [ ! -f "unifi_root_ca.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Minting UniFi Infrastructure Root CA via YubiKey Slot ${SLOT_UNIFI_CA}..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${ROOT_CA_NAME} - UniFi Infrastructure" unifi_root_ca.crt \
            --profile root-ca \
            --key "${KEY_URI_UNIFI}" \
            --not-after=87600h \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Created: unifi_root_ca.crt"
    else
        echo "==> unifi_root_ca.crt already exists. Skipping."
    fi

    if [ ! -f "unifi-ap.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Creating UniFi AP Authenticator Certificate..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${AP_IDENTITY}" unifi-ap.crt unifi-ap.key \
            --profile leaf \
            --ca unifi_root_ca.crt \
            --ca-key "${KEY_URI_UNIFI}" \
            --kty EC --curve "${CURVE}" \
            --not-after=8760h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Created: unifi-ap.crt, unifi-ap.key"
    else
        echo "==> unifi-ap.crt already exists. Skipping."
    fi

    # --------------------------------------------------------------------------
    # Packaging Client PKCS#12 Bundle (macOS Keychain Compatible)
    # --------------------------------------------------------------------------
    echo ""
    if [ ! -f "client.p12" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Packaging client certificate into client.p12..."
        # NOTE (macOS / Apple Keychain Compatibility vs. Modern Defaults):
        # Passing `--legacy` uses RFC 7292 PBES1 (3DES/RC2-40) rather than modern PBES2 (AES-256)
        # strictly to satisfy Apple's legacy SecPKCS12Import parser in Apple Keychain Access.
        step certificate p12 client.p12 client.crt client.key \
            --legacy \
            --ca user_root_ca.crt \
            --ca server_root_ca.crt \
            "${P12_FORCE_ARG[@]:+${P12_FORCE_ARG[@]}}"
        chmod 600 client.p12
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
    if [ "${RUN_MODE}" = "client" ]; then
        if [ ! -f "root_ca.crt" ] || [ ! -f "root_ca.key" ]; then
            echo "❌ Error: root_ca.crt / root_ca.key not found in ${OUTPUT_DIR}." >&2
            echo "   Please run with --full-with-defaults first to initialize the PKI." >&2
            exit 1
        fi

        CLIENT_CRT="${TARGET_CLIENT}.crt"
        CLIENT_KEY="${TARGET_CLIENT}.key"
        CLIENT_P12="${TARGET_CLIENT}.p12"

        if [ -f "${CLIENT_CRT}" ] && [ "${FORCE}" != "true" ]; then
            echo "==> ${CLIENT_CRT} already exists. Skipping (use --force to overwrite)."
        else
            echo "==> Creating Client Certificate (${TARGET_CLIENT})..."
            step certificate create "${TARGET_CLIENT}" "${CLIENT_CRT}" "${CLIENT_KEY}" \
                --profile leaf \
                --ca root_ca.crt \
                --ca-key root_ca.key \
                --kty EC --curve "${CURVE}" \
                --not-after=8760h \
                --no-password --insecure \
                "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
            echo "✔ Created: ${CLIENT_CRT}, ${CLIENT_KEY}"
        fi

        if [ -f "${CLIENT_P12}" ] && [ "${FORCE}" != "true" ]; then
            echo "==> ${CLIENT_P12} already exists. Skipping."
        else
            echo ""
            echo "==> Packaging client certificate into ${CLIENT_P12}..."
            # NOTE (macOS / Apple Keychain Compatibility vs. Modern Defaults):
            # Passing `--legacy` uses RFC 7292 PBES1 (3DES/RC2-40) rather than modern PBES2 (AES-256)
            # strictly to satisfy Apple's legacy SecPKCS12Import parser in Apple Keychain Access.
            step certificate p12 "${CLIENT_P12}" "${CLIENT_CRT}" "${CLIENT_KEY}" \
                --legacy \
                --ca root_ca.crt \
                "${P12_FORCE_ARG[@]:+${P12_FORCE_ARG[@]}}"
            chmod 600 "${CLIENT_P12}"
            echo "✔ Created: ${CLIENT_P12}"
        fi

        echo ""
        echo "=============================================================================="
        echo "Client credentials successfully provisioned in ${OUTPUT_DIR}:"
        echo "  - Certificate : ${CLIENT_CRT}"
        echo "  - Private Key : ${CLIENT_KEY}"
        echo "  - PKCS#12     : ${CLIENT_P12}"
        echo "=============================================================================="
        exit 0
    fi

    # Full Infrastructure Software Bootstrap
    if [ ! -f "root_ca.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Creating Software Root CA (${CURVE})..."
        step certificate create "${ROOT_CA_NAME}" root_ca.crt root_ca.key \
            --profile root-ca \
            --kty EC --curve "${CURVE}" \
            --not-after=87600h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Root CA created: root_ca.crt, root_ca.key"
    else
        echo "==> Root CA already exists (root_ca.crt). Skipping."
    fi

    if [ ! -f "server.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Creating FreeRADIUS Server Certificate for ${RADIUS_IP}..."
        step certificate create "${RADIUS_IP}" server.crt server.key \
            --profile leaf \
            --ca root_ca.crt \
            --ca-key root_ca.key \
            --kty EC --curve "${CURVE}" \
            "${SERVER_SAN_ARGS[@]:+${SERVER_SAN_ARGS[@]}}" \
            --not-after=8760h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Server cert created: server.crt, server.key"
    else
        echo "==> Server certificate already exists (server.crt). Skipping."
    fi

    if [ -f "server.crt" ] && [ -f "server.key" ]; then
        cat server.crt server.key > server.pem
        chmod 600 server.pem
        echo "✔ Created combined server.pem for Alpine FreeRADIUS"
    fi
    if [ -f "root_ca.crt" ]; then
        cp root_ca.crt ca.pem
        echo "✔ Created ca.pem from root_ca.crt"
    fi

    if [ ! -f "unifi-ap.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Creating UniFi AP Authenticator Certificate..."
        step certificate create "${AP_IDENTITY}" unifi-ap.crt unifi-ap.key \
            --profile leaf \
            --ca root_ca.crt \
            --ca-key root_ca.key \
            --kty EC --curve "${CURVE}" \
            --not-after=8760h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ UniFi AP cert created: unifi-ap.crt, unifi-ap.key"
    else
        echo "==> UniFi AP certificate already exists (unifi-ap.crt). Skipping."
    fi

    if [ ! -f "client.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Creating Client Certificate (${CLIENT_IDENTITY})..."
        step certificate create "${CLIENT_IDENTITY}" client.crt client.key \
            --profile leaf \
            --ca root_ca.crt \
            --ca-key root_ca.key \
            --kty EC --curve "${CURVE}" \
            --not-after=8760h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Client cert created: client.crt, client.key"
    else
        echo "==> Client certificate already exists (client.crt). Skipping."
    fi

    if [ ! -f "client.p12" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Packaging client certificate into client.p12..."
        # NOTE (macOS / Apple Keychain Compatibility vs. Modern Defaults):
        # Passing `--legacy` uses RFC 7292 PBES1 (3DES/RC2-40) rather than modern PBES2 (AES-256)
        # strictly to satisfy Apple's legacy SecPKCS12Import parser in Apple Keychain Access.
        step certificate p12 client.p12 client.crt client.key \
            --legacy \
            --ca root_ca.crt \
            "${P12_FORCE_ARG[@]:+${P12_FORCE_ARG[@]}}"
        chmod 600 client.p12
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
