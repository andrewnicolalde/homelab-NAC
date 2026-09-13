#!/usr/bin/env bash
# ==============================================================================
# YubiKey Certificate Authority Hardware Key Generator
# Configured for WPA3-Enterprise 192-bit (CNSA / Suite B) Mode (NIST P-384 / SHA-384)
# ==============================================================================
# Generates hardware-backed private keys inside YubiKey PIV slots with:
#   - Algorithm : ECCP384 (secp384r1)
#   - PIN Policy : ONCE (prompts for PIN once per session)
#   - Touch Policy: ALWAYS (enforces physical hardware touch for every subsequent signature performed with generated keys.)
#
# Slot Architecture:
#   - Slot 9c : RADIUS Server Root CA
#   - Slot 9d : User Endpoints Root CA
#   - Slot 82 : Network Infrastructure Authenticators Root CA
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_usage() {
    cat <<EOF
==============================================================================
YubiKey CA Hardware Key Generation Tool (CNSA P-384)
==============================================================================

Usage:
  $(basename "$0") [action] [options]

Actions (one required):
  --all                 Generate hardware keys for ALL 3 CAs (Slots 9c, 9d, 82)
  --server              Generate hardware key only for RADIUS Server CA (Slot 9c)
  --user                Generate hardware key only for User Endpoints CA (Slot 9d)
  --authenticators      Generate hardware key only for Authenticators CA (Slot 82)

Options:
  --config, -c <file>   Path to environment configuration file (e.g. certs.env)
  --force, -f           Skip confirmation prompts before overwriting keys
  --help, -h            Display this help message

Examples:
  # Re-key all three Certificate Authorities on the YubiKey
  ./$(basename "$0") --all

  # Re-key only the User Endpoints CA
  ./$(basename "$0") --user --force
==============================================================================
EOF
}

# ------------------------------------------------------------------------------
# 1. Argument Parsing
# ------------------------------------------------------------------------------
TARGET_CA=""
FORCE="false"
CONFIG_FILE="${CONFIG_FILE:-${CERTS_ENV:-}}"

POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)
            TARGET_CA="all"
            shift
            ;;
        --server)
            TARGET_CA="server"
            shift
            ;;
        --user)
            TARGET_CA="user"
            shift
            ;;
        --authenticators)
            TARGET_CA="authenticators"
            shift
            ;;
        --force|-f)
            FORCE="true"
            shift
            ;;
        --config|-c)
            CONFIG_FILE="$2"
            shift 2
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

if [ -z "${TARGET_CA}" ]; then
    echo "❌ Error: No action specified." >&2
    echo "   You must specify one of: --all, --server, --user, --authenticators." >&2
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

# Slot mappings with environment overrides (matching directory structure convention)
SLOT_RADIUS_SERVER_CA="${SLOT_RADIUS_SERVER_CA:-${SLOT_SERVER_CA:-9c}}"
SLOT_USER_CLIENT_DEVICES_CA="${SLOT_USER_CLIENT_DEVICES_CA:-${SLOT_USER_CA:-9d}}"
SLOT_NETWORK_INFRASTRUCTURE_AUTHENTICATORS_CA="${SLOT_NETWORK_INFRASTRUCTURE_AUTHENTICATORS_CA:-${SLOT_AUTHENTICATORS_CA:-${SLOT_UNIFI_CA:-82}}}"

# ------------------------------------------------------------------------------
# 2. Dependency & Hardware Verification
# ------------------------------------------------------------------------------
if ! command -v ykman &>/dev/null; then
    echo "❌ Error: 'ykman' (YubiKey Manager CLI) is not installed or not in PATH." >&2
    echo "   Install via Homebrew: brew install ykman" >&2
    exit 1
fi

CONNECTED_DEVICES=$(ykman list 2>&1 || true)
if [[ -z "$CONNECTED_DEVICES" || "$CONNECTED_DEVICES" =~ "No YubiKey detected" ]]; then
    echo "❌ Error: No YubiKey detected. Please plug in a YubiKey and try again." >&2
    exit 1
fi

echo "=============================================================================="
echo "  YubiKey Certificate Authority Key Provisioning"
echo "=============================================================================="
echo "  Connected Device: $(echo "$CONNECTED_DEVICES" | head -n 1)"
echo "  Algorithm       : ECCP384 (NIST P-384 / CNSA 192-bit)"
echo "  PIN Policy      : ONCE"
echo "  Touch Policy    : ALWAYS"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# 3. Helper Functions
# ------------------------------------------------------------------------------
generate_slot_key() {
    local slot="$1"
    local ca_label="$2"

    echo ""
    echo "------------------------------------------------------------------------------"
    echo "==> Target: ${ca_label} (Slot ${slot})"
    echo "------------------------------------------------------------------------------"

    if [ "${FORCE}" != "true" ]; then
        read -r -p "⚠️  Overwrite existing private key in Slot ${slot} for ${ca_label}? [y/N]: " CONFIRM
        if [[ ! "${CONFIRM}" =~ ^[Yy]$ ]]; then
            echo "⏭️  Skipping Slot ${slot}."
            return 0
        fi
    fi

    echo "==> Generating ECCP384 key pair in Slot ${slot}..."
    echo "    (Enter YubiKey management key or PIN if prompted)"
    ykman piv keys generate \
        --algorithm eccp384 \
        --pin-policy ONCE \
        --touch-policy ALWAYS \
        "${slot}" - > /dev/null

    echo "✔ Successfully generated hardware private key in Slot ${slot} (${ca_label})"
}

# ------------------------------------------------------------------------------
# 4. Execution
# ------------------------------------------------------------------------------
case "${TARGET_CA}" in
    server)
        generate_slot_key "${SLOT_RADIUS_SERVER_CA}" "RADIUS Server Root CA"
        ;;
    user)
        generate_slot_key "${SLOT_USER_CLIENT_DEVICES_CA}" "User Endpoints Root CA"
        ;;
    authenticators)
        generate_slot_key "${SLOT_NETWORK_INFRASTRUCTURE_AUTHENTICATORS_CA}" "Network Infrastructure Authenticators Root CA"
        ;;
    all)
        echo ""
        echo "⚠️  WARNING: You are about to re-key ALL THREE Certificate Authorities on your YubiKey."
        echo "   - Slot ${SLOT_RADIUS_SERVER_CA} : RADIUS Server Root CA"
        echo "   - Slot ${SLOT_USER_CLIENT_DEVICES_CA} : User Endpoints Root CA"
        echo "   - Slot ${SLOT_NETWORK_INFRASTRUCTURE_AUTHENTICATORS_CA} : Network Infrastructure Authenticators Root CA"
        echo ""
        if [ "${FORCE}" != "true" ]; then
            read -r -p "Are you sure you want to proceed? [y/N]: " CONFIRM_ALL
            if [[ ! "${CONFIRM_ALL}" =~ ^[Yy]$ ]]; then
                echo "Aborted."
                exit 0
            fi
        fi

        generate_slot_key "${SLOT_RADIUS_SERVER_CA}" "RADIUS Server Root CA"
        generate_slot_key "${SLOT_USER_CLIENT_DEVICES_CA}" "User Endpoints Root CA"
        generate_slot_key "${SLOT_NETWORK_INFRASTRUCTURE_AUTHENTICATORS_CA}" "Network Infrastructure Authenticators Root CA"
        ;;
esac

echo ""
echo "=============================================================================="
echo "✔ YubiKey Hardware CA key generation completed successfully."
echo "  Next step: Run './generate-certs.sh --full-with-defaults --force' to mint"
echo "  the X.509 root CA certificates and infrastructure credentials."
echo "=============================================================================="
