#!/usr/bin/env bash
# ==============================================================================
# Certificate Generation Script for 802.1X / EAP-TLS using Smallstep CLI (`step`)
# Configured for WPA3-Enterprise 192-bit (CNSA / Suite B) Mode (NIST P-384 / SHA-384)
# ==============================================================================
# Supports two modes of operation:
#   1. Software Mode (Default):
#      - Mints software Root CAs on disk.
#      - Signs server, authenticator, and client certificates via software keys.
#   2. Hardware Root of Trust Mode (--yubikey or USE_YUBIKEY=true):
#      - Operates with 3 distinct Root CAs residing on a single YubiKey 5:
#          * Slot 9c: RADIUS Server Root CA (radius-server/server_root_ca.crt)
#          * Slot 9d: User Endpoints Root CA (user-client-devices/user_root_ca.crt)
#          * Slot 82: Authenticators Root CA (network-infrastructure-authenticators/authenticators_root_ca.crt)
#      - Prompts for PIV PIN interactively into process memory; never writes PIN to disk.
#      - Zero disk exposure for Root CA private keys; physical touch enforced.
#
# Directory Structure Emitted:
#   certs/
#   ├── radius-server/
#   │   ├── server_root_ca.crt                  # RADIUS Server Root CA (Slot 9c)
#   │   └── server.pem                          # Unified server certificate + key
#   ├── user-client-devices/
#   │   ├── user_root_ca.crt                    # User Endpoints Root CA (Slot 9d)
#   │   └── <device-name>/                      # Generated on-demand via --client <identity>
#   │       └── <device-name>.p12               # Encrypted PKCS#12 bundle (identity + trust chain)
#   └── network-infrastructure-authenticators/
#       ├── authenticators_root_ca.crt          # Authenticators Root CA (Slot 82)
#       ├── authenticator.crt                   # Authenticator leaf certificate (e.g. APs)
#       └── authenticator.key                   # Authenticator private key
#
# Execution Modes (One Required):
#   --full-with-defaults : Bootstrap infrastructure (3 CAs, FreeRADIUS server, Network AP)
#   --server             : Generate/rotate FreeRADIUS server credentials (radius-server/)
#   --client <identity>  : Onboard an individual client device (user-client-devices/<identity>/)
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
  $(basename "$0") --server [options]
  $(basename "$0") --client <identity> [options]

Modes (one required):
  --full-with-defaults    Bootstrap full infrastructure suite:
                            - radius-server/ (Server CA + unified server.pem)
                            - user-client-devices/ (User Endpoints CA only)
                            - network-infrastructure-authenticators/ (CA + authenticator certs)
  --server                Generate/rotate credentials exclusively for the FreeRADIUS
                          server (radius-server/server.pem) signed by Slot 9c
  --client <identity>     Provision an individual client device into:
                          user-client-devices/<identity>/<identity>.p12 (signed by Slot 9d)

Options:
  --config, -c <file>     Path to environment configuration file (e.g. certs.env)
  --output-dir, -o <dir>  Target directory for generated certificates (default: cwd)
  --yubikey               Use YubiKey hardware root of trust (3-CA architecture)
  --force, -f             Overwrite existing certificates/keys if already present
  --help, -h              Display this help message

Examples:
  # Bootstrap initial infrastructure PKI (3 CAs + Server + Authenticator)
  ./$(basename "$0") --full-with-defaults

  # Onboard a new client device
  ./$(basename "$0") --client client-device-01

  # Force re-issuance of a specific client credential
  ./$(basename "$0") --client client-device-01 --force
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
        --server)
            RUN_MODE="server"
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
    echo "   You must specify either --full-with-defaults, --server, or --client <identity>." >&2
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

RADIUS_SERVER_NAME="${RADIUS_SERVER_NAME:-radius.internal.example.com}"
ROOT_CA_NAME="${ROOT_CA_NAME:-Enterprise Root CA}"
AP_IDENTITY="${AP_IDENTITY:-unifi-aps}"
CURVE="${CURVE:-P-384}"

# PIV Slot mappings for YubiKey 3-CA architecture (matching directory convention)
SLOT_RADIUS_SERVER_CA="${SLOT_RADIUS_SERVER_CA:-${SLOT_SERVER_CA:-9c}}"
SLOT_USER_CLIENT_DEVICES_CA="${SLOT_USER_CLIENT_DEVICES_CA:-${SLOT_USER_CA:-9d}}"
SLOT_NETWORK_INFRASTRUCTURE_AUTHENTICATORS_CA="${SLOT_NETWORK_INFRASTRUCTURE_AUTHENTICATORS_CA:-${SLOT_AUTHENTICATORS_CA:-${SLOT_UNIFI_CA:-82}}}"

# Determine output directory and subfolder layout
OUTPUT_DIR="${OUTPUT_DIR:-${PWD}}"
SERVER_DIR="${OUTPUT_DIR}/radius-server"
USER_DIR="${OUTPUT_DIR}/user-client-devices"
INFRA_DIR="${OUTPUT_DIR}/network-infrastructure-authenticators"

mkdir -p "${SERVER_DIR}" "${USER_DIR}" "${INFRA_DIR}"

echo "=============================================================================="
echo "  CNSA 192-bit Certificate Generation (step CLI)"
echo "=============================================================================="
echo "  Mode            : $([ "${USE_YUBIKEY}" = "true" ] && echo "YubiKey Hardware Root of Trust (3-CA)" || echo "Software Root CAs (Disk-backed 3-CA)")"
if [ "${RUN_MODE}" = "full" ]; then
    echo "  Action          : Full Infrastructure Bootstrap (--full-with-defaults)"
    echo "  RADIUS Server   : ${RADIUS_SERVER_NAME}"
elif [ "${RUN_MODE}" = "server" ]; then
    echo "  Action          : Server Certificate Generation/Rotation (--server)"
    echo "  RADIUS Server   : ${RADIUS_SERVER_NAME}"
else
    echo "  Action          : Client Device Onboarding (--client)"
    echo "  Client Identity : ${TARGET_CLIENT}"
fi
echo "  Output Dir      : ${OUTPUT_DIR}"
echo "    ├── radius-server/"
echo "    ├── user-client-devices/"
echo "    └── network-infrastructure-authenticators/"
echo "  Root CA Base Prefix for all Certificate Authorities: ${ROOT_CA_NAME}"
echo "  Elliptic Curve  : ${CURVE} (ECDSA-SHA384)"
echo "  Force Overwrite : ${FORCE}"
echo "=============================================================================="

# Optional additional Subject Alternative Names (SANs)
if [ -z "${ADDITIONAL_SANS+x}" ]; then
    ADDITIONAL_SANS=()
fi

SERVER_SAN_ARGS=(--san "${RADIUS_SERVER_NAME}")
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

    KEY_URI_SERVER="yubikey:slot-id=${SLOT_RADIUS_SERVER_CA}?pin-value=${YUBIKEY_PIN}"
    KEY_URI_USER="yubikey:slot-id=${SLOT_USER_CLIENT_DEVICES_CA}?pin-value=${YUBIKEY_PIN}"
    KEY_URI_UNIFI="yubikey:slot-id=${SLOT_NETWORK_INFRASTRUCTURE_AUTHENTICATORS_CA}?pin-value=${YUBIKEY_PIN}"

    # ==========================================================================
    # BRANCH A: Client Device Onboarding Mode (--client <identity>)
    # ==========================================================================
    if [ "${RUN_MODE}" = "client" ]; then
        echo ""
        echo "--- User Endpoints PKI (Slot ${SLOT_USER_CLIENT_DEVICES_CA}) ---"

        # Ensure User Endpoints Root CA exists in user-client-devices/
        if [ ! -f "${USER_DIR}/user_root_ca.crt" ]; then
            echo "==> Minting User Endpoints Root CA via YubiKey Slot ${SLOT_USER_CLIENT_DEVICES_CA}..."
            echo "    >>> Touch your YubiKey when LED flashes <<<"
            step certificate create "${ROOT_CA_NAME} - User Endpoints" "${USER_DIR}/user_root_ca.crt" \
                --profile root-ca \
                --key "${KEY_URI_USER}" \
                --not-after=87600h \
                "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
            echo "✔ Created: ${USER_DIR}/user_root_ca.crt"
        else
            echo "==> ${USER_DIR}/user_root_ca.crt already exists. Reusing."
        fi

        CLIENT_DEVICE_DIR="${USER_DIR}/${TARGET_CLIENT}"
        mkdir -p "${CLIENT_DEVICE_DIR}"

        CLIENT_CRT="${CLIENT_DEVICE_DIR}/${TARGET_CLIENT}.crt"
        CLIENT_KEY="${CLIENT_DEVICE_DIR}/${TARGET_CLIENT}.key"
        CLIENT_P12="${CLIENT_DEVICE_DIR}/${TARGET_CLIENT}.p12"

        if [ -f "${CLIENT_P12}" ] && [ "${FORCE}" != "true" ]; then
            echo "==> ${CLIENT_P12} already exists. Skipping (use --force to overwrite)."
        else
            echo ""
            echo "==> Creating Client Certificate (${TARGET_CLIENT})..."
            echo "    >>> Touch your YubiKey when LED flashes <<<"
            step certificate create "${TARGET_CLIENT}" "${CLIENT_CRT}" "${CLIENT_KEY}" \
                --profile leaf \
                --ca "${USER_DIR}/user_root_ca.crt" \
                --ca-key "${KEY_URI_USER}" \
                --kty EC --curve "${CURVE}" \
                --not-after=8760h \
                --no-password --insecure \
                "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"

            echo ""
            echo "==> Packaging client certificate into ${CLIENT_P12}..."
            CA_ARGS=(--ca "${USER_DIR}/user_root_ca.crt")
            if [ -f "${SERVER_DIR}/server_root_ca.crt" ]; then
                CA_ARGS+=(--ca "${SERVER_DIR}/server_root_ca.crt")
            fi

            # Package using legacy PBES1 strictly for macOS Keychain Access compatibility
            step certificate p12 "${CLIENT_P12}" "${CLIENT_CRT}" "${CLIENT_KEY}" \
                --legacy \
                "${CA_ARGS[@]:+${CA_ARGS[@]}}" \
                "${P12_FORCE_ARG[@]:+${P12_FORCE_ARG[@]}}"
            chmod 600 "${CLIENT_P12}"

            # Security Best Practice: Purge temporary unencrypted private key and cert
            rm -f "${CLIENT_CRT}" "${CLIENT_KEY}"
            echo "✔ Created encrypted bundle: ${CLIENT_P12}"
            echo "✔ Cleaned up temporary unencrypted plaintext key and certificate"
        fi

        echo ""
        echo "=============================================================================="
        echo "Client credentials successfully provisioned:"
        echo "  - Identity    : ${TARGET_CLIENT}"
        echo "  - Directory   : ${CLIENT_DEVICE_DIR}"
        echo "  - PKCS#12     : ${CLIENT_P12}"
        echo "=============================================================================="
        exit 0
    fi

    # ==========================================================================
    # BRANCH B: Server Certificate Mode (--server)
    # ==========================================================================
    if [ "${RUN_MODE}" = "server" ]; then
        echo ""
        echo "--- RADIUS Server PKI (Slot ${SLOT_RADIUS_SERVER_CA}) ---"
        if [ ! -f "${SERVER_DIR}/server_root_ca.crt" ]; then
            echo "❌ Error: server_root_ca.crt not found in ${SERVER_DIR}." >&2
            echo "   Please run with --full-with-defaults first to initialize the PKI." >&2
            exit 1
        fi

        if [ -f "${SERVER_DIR}/server.pem" ] && [ "${FORCE}" != "true" ]; then
            echo "==> ${SERVER_DIR}/server.pem already exists. Skipping (use --force to overwrite)."
        else
            TMP_SERVER_CRT="${SERVER_DIR}/server.crt.tmp"
            TMP_SERVER_KEY="${SERVER_DIR}/server.key.tmp"

            echo "==> Creating FreeRADIUS Server Certificate for ${RADIUS_SERVER_NAME}..."
            echo "    >>> Touch your YubiKey when LED flashes <<<"
            step certificate create "${RADIUS_SERVER_NAME}" "${TMP_SERVER_CRT}" "${TMP_SERVER_KEY}" \
                --profile leaf \
                --ca "${SERVER_DIR}/server_root_ca.crt" \
                --ca-key "${KEY_URI_SERVER}" \
                --kty EC --curve "${CURVE}" \
                "${SERVER_SAN_ARGS[@]:+${SERVER_SAN_ARGS[@]}}" \
                --not-after=8760h \
                --no-password --insecure \
                "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"

            cat "${TMP_SERVER_CRT}" "${TMP_SERVER_KEY}" > "${SERVER_DIR}/server.pem"
            chmod 600 "${SERVER_DIR}/server.pem"
            rm -f "${TMP_SERVER_CRT}" "${TMP_SERVER_KEY}"
            echo "✔ Created unified server.pem (certificate + private key)"
        fi

        echo ""
        echo "=============================================================================="
        echo "FreeRADIUS Server credentials successfully generated in ${SERVER_DIR}:"
        echo "  - Root CA     : ${SERVER_DIR}/server_root_ca.crt"
        echo "  - Combined PEM: ${SERVER_DIR}/server.pem"
        echo "=============================================================================="
        exit 0
    fi

    # ==========================================================================
    # BRANCH C: Full Infrastructure Bootstrap Mode (--full-with-defaults)
    # ==========================================================================
    # --------------------------------------------------------------------------
    # YubiKey CA 1: RADIUS Server Root CA (Slot 9c) & Server PEM
    # --------------------------------------------------------------------------
    echo ""
    echo "--- [1/3] RADIUS Server PKI (Slot ${SLOT_RADIUS_SERVER_CA}) ---"
    if [ ! -f "${SERVER_DIR}/server_root_ca.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Minting RADIUS Server Root CA via YubiKey Slot ${SLOT_RADIUS_SERVER_CA}..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${ROOT_CA_NAME} - RADIUS Server" "${SERVER_DIR}/server_root_ca.crt" \
            --profile root-ca \
            --key "${KEY_URI_SERVER}" \
            --not-after=87600h \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Created: ${SERVER_DIR}/server_root_ca.crt"
    else
        echo "==> ${SERVER_DIR}/server_root_ca.crt already exists. Skipping."
    fi

    if [ ! -f "${SERVER_DIR}/server.pem" ] || [ "${FORCE}" = "true" ]; then
        TMP_SERVER_CRT="${SERVER_DIR}/server.crt.tmp"
        TMP_SERVER_KEY="${SERVER_DIR}/server.key.tmp"

        echo "==> Creating FreeRADIUS Server Certificate for ${RADIUS_SERVER_NAME}..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${RADIUS_SERVER_NAME}" "${TMP_SERVER_CRT}" "${TMP_SERVER_KEY}" \
            --profile leaf \
            --ca "${SERVER_DIR}/server_root_ca.crt" \
            --ca-key "${KEY_URI_SERVER}" \
            --kty EC --curve "${CURVE}" \
            "${SERVER_SAN_ARGS[@]:+${SERVER_SAN_ARGS[@]}}" \
            --not-after=8760h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"

        cat "${TMP_SERVER_CRT}" "${TMP_SERVER_KEY}" > "${SERVER_DIR}/server.pem"
        chmod 600 "${SERVER_DIR}/server.pem"
        rm -f "${TMP_SERVER_CRT}" "${TMP_SERVER_KEY}"
        echo "✔ Created unified ${SERVER_DIR}/server.pem"
    else
        echo "==> ${SERVER_DIR}/server.pem already exists. Skipping."
    fi

    # --------------------------------------------------------------------------
    # YubiKey CA 2: User Endpoints Root CA (Slot 9d)
    # (Client device certificates are provisioned on-demand via --client <name>)
    # --------------------------------------------------------------------------
    echo ""
    echo "--- [2/3] User Endpoints PKI (Slot ${SLOT_USER_CLIENT_DEVICES_CA}) ---"
    if [ ! -f "${USER_DIR}/user_root_ca.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Minting User Endpoints Root CA via YubiKey Slot ${SLOT_USER_CLIENT_DEVICES_CA}..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${ROOT_CA_NAME} - User Endpoints" "${USER_DIR}/user_root_ca.crt" \
            --profile root-ca \
            --key "${KEY_URI_USER}" \
            --not-after=87600h \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Created: ${USER_DIR}/user_root_ca.crt"
    else
        echo "==> ${USER_DIR}/user_root_ca.crt already exists. Skipping."
    fi

    # --------------------------------------------------------------------------
    # YubiKey CA 3: Network Infrastructure Authenticators Root CA (Slot 82)
    # --------------------------------------------------------------------------
    echo ""
    echo "--- [3/3] Network Infrastructure Authenticators PKI (Slot ${SLOT_NETWORK_INFRASTRUCTURE_AUTHENTICATORS_CA}) ---"
    if [ ! -f "${INFRA_DIR}/authenticators_root_ca.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Minting Authenticators Root CA via YubiKey Slot ${SLOT_NETWORK_INFRASTRUCTURE_AUTHENTICATORS_CA}..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${ROOT_CA_NAME} - Network Infrastructure Authenticators" "${INFRA_DIR}/authenticators_root_ca.crt" \
            --profile root-ca \
            --key "${KEY_URI_UNIFI}" \
            --not-after=87600h \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Created: ${INFRA_DIR}/authenticators_root_ca.crt"
    else
        echo "==> ${INFRA_DIR}/authenticators_root_ca.crt already exists. Skipping."
    fi

    if [ ! -f "${INFRA_DIR}/authenticator.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Creating Authenticator Certificate..."
        echo "    >>> Touch your YubiKey when LED flashes <<<"
        step certificate create "${AP_IDENTITY}" "${INFRA_DIR}/authenticator.crt" "${INFRA_DIR}/authenticator.key" \
            --profile leaf \
            --ca "${INFRA_DIR}/authenticators_root_ca.crt" \
            --ca-key "${KEY_URI_UNIFI}" \
            --kty EC --curve "${CURVE}" \
            --not-after=8760h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Created: ${INFRA_DIR}/authenticator.crt, ${INFRA_DIR}/authenticator.key"
    else
        echo "==> ${INFRA_DIR}/authenticator.crt already exists. Skipping."
    fi

    echo ""
    echo "=============================================================================="
    echo "Infrastructure Bootstrap Complete in ${OUTPUT_DIR}:"
    echo "  [radius-server/]"
    echo "    - server_root_ca.crt      : RADIUS Server Root CA"
    echo "    - server.pem              : FreeRADIUS Server Certificate & Key"
    echo "  [user-client-devices/]"
    echo "    - user_root_ca.crt        : User Endpoints Root CA"
    echo "  [network-infrastructure-authenticators/]"
    echo "    - authenticators_root_ca.crt : Authenticators Root CA"
    echo "    - authenticator.crt/.key  : Authenticator Client Certificate & Key"
    echo ""
    echo "👉 To onboard a client device, run:"
    echo "   ./$(basename "$0") --client <device-name>"
    echo "=============================================================================="

else
    # --------------------------------------------------------------------------
    # Software Mode (Standard disk-based Root CAs)
    # --------------------------------------------------------------------------
    if [ "${RUN_MODE}" = "client" ]; then
        if [ ! -f "${USER_DIR}/user_root_ca.crt" ] || [ ! -f "${USER_DIR}/user_root_ca.key" ]; then
            echo "❌ Error: user_root_ca.crt / user_root_ca.key not found in ${USER_DIR}." >&2
            echo "   Please run with --full-with-defaults first to initialize the PKI." >&2
            exit 1
        fi

        CLIENT_DEVICE_DIR="${USER_DIR}/${TARGET_CLIENT}"
        mkdir -p "${CLIENT_DEVICE_DIR}"

        CLIENT_CRT="${CLIENT_DEVICE_DIR}/${TARGET_CLIENT}.crt"
        CLIENT_KEY="${CLIENT_DEVICE_DIR}/${TARGET_CLIENT}.key"
        CLIENT_P12="${CLIENT_DEVICE_DIR}/${TARGET_CLIENT}.p12"

        if [ -f "${CLIENT_P12}" ] && [ "${FORCE}" != "true" ]; then
            echo "==> ${CLIENT_P12} already exists. Skipping (use --force to overwrite)."
        else
            echo "==> Creating Client Certificate (${TARGET_CLIENT})..."
            step certificate create "${TARGET_CLIENT}" "${CLIENT_CRT}" "${CLIENT_KEY}" \
                --profile leaf \
                --ca "${USER_DIR}/user_root_ca.crt" \
                --ca-key "${USER_DIR}/user_root_ca.key" \
                --kty EC --curve "${CURVE}" \
                --not-after=8760h \
                --no-password --insecure \
                "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"

            echo "==> Packaging client certificate into ${CLIENT_P12}..."
            CA_ARGS=(--ca "${USER_DIR}/user_root_ca.crt")
            if [ -f "${SERVER_DIR}/server_root_ca.crt" ]; then
                CA_ARGS+=(--ca "${SERVER_DIR}/server_root_ca.crt")
            fi

            step certificate p12 "${CLIENT_P12}" "${CLIENT_CRT}" "${CLIENT_KEY}" \
                --legacy \
                "${CA_ARGS[@]:+${CA_ARGS[@]}}" \
                "${P12_FORCE_ARG[@]:+${P12_FORCE_ARG[@]}}"
            chmod 600 "${CLIENT_P12}"

            rm -f "${CLIENT_CRT}" "${CLIENT_KEY}"
            echo "✔ Created encrypted bundle: ${CLIENT_P12}"
        fi

        echo ""
        echo "=============================================================================="
        echo "Client credentials successfully provisioned:"
        echo "  - Identity    : ${TARGET_CLIENT}"
        echo "  - Directory   : ${CLIENT_DEVICE_DIR}"
        echo "  - PKCS#12     : ${CLIENT_P12}"
        echo "=============================================================================="
        exit 0
    fi

    # Server Mode
    if [ "${RUN_MODE}" = "server" ]; then
        if [ ! -f "${SERVER_DIR}/server_root_ca.crt" ] || [ ! -f "${SERVER_DIR}/server_root_ca.key" ]; then
            echo "❌ Error: server_root_ca.crt not found in ${SERVER_DIR}." >&2
            echo "   Please run with --full-with-defaults first to initialize the PKI." >&2
            exit 1
        fi

        if [ -f "${SERVER_DIR}/server.pem" ] && [ "${FORCE}" != "true" ]; then
            echo "==> ${SERVER_DIR}/server.pem already exists. Skipping (use --force to overwrite)."
        else
            TMP_SERVER_CRT="${SERVER_DIR}/server.crt.tmp"
            TMP_SERVER_KEY="${SERVER_DIR}/server.key.tmp"

            echo "==> Creating FreeRADIUS Server Certificate for ${RADIUS_SERVER_NAME}..."
            step certificate create "${RADIUS_SERVER_NAME}" "${TMP_SERVER_CRT}" "${TMP_SERVER_KEY}" \
                --profile leaf \
                --ca "${SERVER_DIR}/server_root_ca.crt" \
                --ca-key "${SERVER_DIR}/server_root_ca.key" \
                --kty EC --curve "${CURVE}" \
                "${SERVER_SAN_ARGS[@]:+${SERVER_SAN_ARGS[@]}}" \
                --not-after=8760h \
                --no-password --insecure \
                "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"

            cat "${TMP_SERVER_CRT}" "${TMP_SERVER_KEY}" > "${SERVER_DIR}/server.pem"
            chmod 600 "${SERVER_DIR}/server.pem"
            rm -f "${TMP_SERVER_CRT}" "${TMP_SERVER_KEY}"
            echo "✔ Created: ${SERVER_DIR}/server.pem"
        fi

        echo ""
        echo "=============================================================================="
        echo "FreeRADIUS Server credentials successfully generated in ${SERVER_DIR}:"
        echo "  - Root CA     : ${SERVER_DIR}/server_root_ca.crt"
        echo "  - Combined PEM: ${SERVER_DIR}/server.pem"
        echo "=============================================================================="
        exit 0
    fi

    # Full Bootstrap Software Mode
    if [ ! -f "${SERVER_DIR}/server_root_ca.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Creating Software RADIUS Server Root CA..."
        step certificate create "${ROOT_CA_NAME} - RADIUS Server" "${SERVER_DIR}/server_root_ca.crt" "${SERVER_DIR}/server_root_ca.key" \
            --profile root-ca \
            --kty EC --curve "${CURVE}" \
            --not-after=87600h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Server Root CA created: ${SERVER_DIR}/server_root_ca.crt"
    fi

    if [ ! -f "${SERVER_DIR}/server.pem" ] || [ "${FORCE}" = "true" ]; then
        TMP_SERVER_CRT="${SERVER_DIR}/server.crt.tmp"
        TMP_SERVER_KEY="${SERVER_DIR}/server.key.tmp"

        echo "==> Creating FreeRADIUS Server Certificate for ${RADIUS_SERVER_NAME}..."
        step certificate create "${RADIUS_SERVER_NAME}" "${TMP_SERVER_CRT}" "${TMP_SERVER_KEY}" \
            --profile leaf \
            --ca "${SERVER_DIR}/server_root_ca.crt" \
            --ca-key "${SERVER_DIR}/server_root_ca.key" \
            --kty EC --curve "${CURVE}" \
            "${SERVER_SAN_ARGS[@]:+${SERVER_SAN_ARGS[@]}}" \
            --not-after=8760h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"

        cat "${TMP_SERVER_CRT}" "${TMP_SERVER_KEY}" > "${SERVER_DIR}/server.pem"
        chmod 600 "${SERVER_DIR}/server.pem"
        rm -f "${TMP_SERVER_CRT}" "${TMP_SERVER_KEY}"
        echo "✔ Server PEM created: ${SERVER_DIR}/server.pem"
    fi

    if [ ! -f "${USER_DIR}/user_root_ca.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Creating Software User Endpoints Root CA..."
        step certificate create "${ROOT_CA_NAME} - User Endpoints" "${USER_DIR}/user_root_ca.crt" "${USER_DIR}/user_root_ca.key" \
            --profile root-ca \
            --kty EC --curve "${CURVE}" \
            --not-after=87600h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ User Endpoints Root CA created: ${USER_DIR}/user_root_ca.crt"
    fi

    if [ ! -f "${INFRA_DIR}/authenticators_root_ca.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Creating Software Authenticators Root CA..."
        step certificate create "${ROOT_CA_NAME} - Network Infrastructure Authenticators" "${INFRA_DIR}/authenticators_root_ca.crt" "${INFRA_DIR}/authenticators_root_ca.key" \
            --profile root-ca \
            --kty EC --curve "${CURVE}" \
            --not-after=87600h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Authenticators Root CA created: ${INFRA_DIR}/authenticators_root_ca.crt"
    fi

    if [ ! -f "${INFRA_DIR}/authenticator.crt" ] || [ "${FORCE}" = "true" ]; then
        echo "==> Creating Authenticator Certificate..."
        step certificate create "${AP_IDENTITY}" "${INFRA_DIR}/authenticator.crt" "${INFRA_DIR}/authenticator.key" \
            --profile leaf \
            --ca "${INFRA_DIR}/authenticators_root_ca.crt" \
            --ca-key "${INFRA_DIR}/authenticators_root_ca.key" \
            --kty EC --curve "${CURVE}" \
            --not-after=8760h \
            --no-password --insecure \
            "${FORCE_ARG[@]:+${FORCE_ARG[@]}}"
        echo "✔ Authenticator cert created: ${INFRA_DIR}/authenticator.crt, ${INFRA_DIR}/authenticator.key"
    fi

    echo ""
    echo "=============================================================================="
    echo "Software Infrastructure Bootstrap Complete in ${OUTPUT_DIR}:"
    echo "  [radius-server/]"
    echo "    - server_root_ca.crt         : RADIUS Server Root CA"
    echo "    - server.pem                 : FreeRADIUS Server Certificate & Key"
    echo "  [user-client-devices/]"
    echo "    - user_root_ca.crt           : User Endpoints Root CA"
    echo "  [network-infrastructure-authenticators/]"
    echo "    - authenticators_root_ca.crt : Authenticators Root CA"
    echo "    - authenticator.crt/.key     : Authenticator Certificate & Key"
    echo ""
    echo "👉 To onboard a client device, run:"
    echo "   ./$(basename "$0") --client <device-name>"
    echo "=============================================================================="
fi
