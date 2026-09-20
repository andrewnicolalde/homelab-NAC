#!/usr/bin/env bash
# ==============================================================================
# Apple Configuration Profile (.mobileconfig) Generator for 802.1X EAP-TLS
# ==============================================================================
# Generates a .mobileconfig file that bundles:
#   1. RADIUS Server Root CA certificate (scoped trust anchor)
#   2. Client PKCS#12 identity (certificate + private key)
#   3. Wi-Fi payload for WPA3-Enterprise EAP-TLS authentication
#
# The Root CA trust is scoped exclusively to 802.1X on the configured SSID
# via PayloadCertificateAnchorUUID and TLSTrustedServerNames — the CA will
# NOT be trusted system-wide for web browsing / HTTPS.
#
# Security Design:
#   - WPA3-Enterprise only (hard-coded, non-configurable)
#   - EAP-TLS only (hard-coded, non-configurable)
#   - TLS 1.2 only (hard-coded, non-configurable)
#   - Static trust pinning via PayloadCertificateAnchorUUID (hard-coded)
#   - PKCS#12 password is NOT embedded — users must enter it at install time
#     (the password must be transmitted/received out-of-band)
#   - Profiles are generated unsigned (signing is planned for a future version)
#
# Dependencies:
#   - /usr/libexec/PlistBuddy (ships with macOS)
#   - plutil (ships with macOS)
#   - openssl (ships with macOS)
#
# Usage:
#   ./generate-mobileconfig.sh \
#       --server-ca certs/radius-server/server_root_ca.crt \
#       --client-p12 certs/user-client-devices/mydevice/mydevice.p12 \
#       --client-name mydevice \
#       --output certs/user-client-devices/mydevice/mydevice.mobileconfig
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLISTBUDDY="/usr/libexec/PlistBuddy"

# ==============================================================================
# Usage
# ==============================================================================
show_usage() {
    cat <<EOF
==============================================================================
Apple Configuration Profile (.mobileconfig) Generator for 802.1X EAP-TLS
==============================================================================

Generates a .mobileconfig profile for WPA3-Enterprise EAP-TLS authentication.

Security properties (hard-coded, non-configurable):
  - Encryption     : WPA3-Enterprise only
  - Authentication : EAP-TLS only (type 13)
  - TLS Version    : TLS 1.2 only
  - Trust          : Static server validation via PayloadCertificateAnchorUUID
  - P12 Password   : NOT embedded (entered by user at install time)
  - Profile Signing: Unsigned (signing planned for future version)

Usage:
  $(basename "$0") [options]

Required:
  --server-ca <path>         Path to RADIUS Server Root CA certificate (PEM or DER)
  --client-p12 <path>        Path to client PKCS#12 identity bundle
  --client-name <name>       Client device identity name (e.g., "mydevice")

Optional:
  --ssid <ssid>              Wi-Fi SSID (env: WIFI_SSID, default: ENTERPRISE-WIFI)
  --radius-server-name <cn>  RADIUS server CN (env: RADIUS_SERVER_NAME)
  --output <path>            Output .mobileconfig path (default: <client-name>.mobileconfig)
  --identifier <id>          Reverse-DNS profile identifier (default: com.homelab.wifi.eap-tls)
  --force, -f                Overwrite existing output file
  --help, -h                 Display this help message

Examples:
  # Generate profile with defaults from certs.env
  ./$(basename "$0") \\
      --server-ca certs/radius-server/server_root_ca.crt \\
      --client-p12 certs/user-client-devices/mydevice/mydevice.p12 \\
      --client-name mydevice

  # Generate profile with explicit SSID and output path
  ./$(basename "$0") \\
      --server-ca server_root_ca.crt \\
      --client-p12 mydevice.p12 \\
      --client-name mydevice \\
      --ssid MY-NETWORK \\
      --output mydevice.mobileconfig
==============================================================================
EOF
}

# ==============================================================================
# 1. Argument Parsing & Configuration
# ==============================================================================
SERVER_CA_PATH=""
CLIENT_P12_PATH=""
CLIENT_NAME=""
WIFI_SSID="${WIFI_SSID:-ENTERPRISE-WIFI}"
RADIUS_SERVER_NAME="${RADIUS_SERVER_NAME:-radius.internal.example.com}"
OUTPUT_PATH=""
PROFILE_IDENTIFIER="${PROFILE_IDENTIFIER:-com.homelab.wifi.eap-tls}"
FORCE="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-ca)
            SERVER_CA_PATH="$2"
            shift 2
            ;;
        --client-p12)
            CLIENT_P12_PATH="$2"
            shift 2
            ;;
        --client-name)
            CLIENT_NAME="$2"
            shift 2
            ;;
        --ssid)
            WIFI_SSID="$2"
            shift 2
            ;;
        --radius-server-name)
            RADIUS_SERVER_NAME="$2"
            shift 2
            ;;
        --output)
            OUTPUT_PATH="$2"
            shift 2
            ;;
        --identifier)
            PROFILE_IDENTIFIER="$2"
            shift 2
            ;;
        --force|-f)
            FORCE="true"
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            echo "❌ Error: Unknown option: $1" >&2
            show_usage >&2
            exit 1
            ;;
    esac
done

# Source optional configuration file (matching generate-certs.sh pattern)
if [ -n "${CONFIG_FILE:-}" ] && [ -f "${CONFIG_FILE}" ]; then
    # shellcheck source=/dev/null
    source "${CONFIG_FILE}"
    # Re-apply env defaults after sourcing (env vars set by config file)
    WIFI_SSID="${WIFI_SSID:-ENTERPRISE-WIFI}"
    RADIUS_SERVER_NAME="${RADIUS_SERVER_NAME:-radius.internal.example.com}"
elif [ -f "./certs.env" ]; then
    # shellcheck source=/dev/null
    source "./certs.env"
    WIFI_SSID="${WIFI_SSID:-ENTERPRISE-WIFI}"
    RADIUS_SERVER_NAME="${RADIUS_SERVER_NAME:-radius.internal.example.com}"
elif [ -f "${SCRIPT_DIR}/certs.env" ]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/certs.env"
    WIFI_SSID="${WIFI_SSID:-ENTERPRISE-WIFI}"
    RADIUS_SERVER_NAME="${RADIUS_SERVER_NAME:-radius.internal.example.com}"
fi

# Validate required arguments
MISSING_ARGS=()
[ -z "${SERVER_CA_PATH}" ] && MISSING_ARGS+=("--server-ca")
[ -z "${CLIENT_P12_PATH}" ] && MISSING_ARGS+=("--client-p12")
[ -z "${CLIENT_NAME}" ] && MISSING_ARGS+=("--client-name")

if [ ${#MISSING_ARGS[@]} -gt 0 ]; then
    echo "❌ Error: Missing required arguments: ${MISSING_ARGS[*]}" >&2
    echo "" >&2
    show_usage >&2
    exit 1
fi

# Validate input files exist
if [ ! -f "${SERVER_CA_PATH}" ]; then
    echo "❌ Error: Server CA certificate not found: ${SERVER_CA_PATH}" >&2
    exit 1
fi
if [ ! -f "${CLIENT_P12_PATH}" ]; then
    echo "❌ Error: Client P12 bundle not found: ${CLIENT_P12_PATH}" >&2
    exit 1
fi

# Default output path
if [ -z "${OUTPUT_PATH}" ]; then
    OUTPUT_PATH="$(dirname "${CLIENT_P12_PATH}")/${CLIENT_NAME}.mobileconfig"
fi

# Check for existing output
if [ -f "${OUTPUT_PATH}" ] && [ "${FORCE}" != "true" ]; then
    echo "❌ Error: Output file already exists: ${OUTPUT_PATH}" >&2
    echo "   Use --force to overwrite." >&2
    exit 1
fi

# Verify macOS tooling is available
if [ ! -x "${PLISTBUDDY}" ]; then
    echo "❌ Error: PlistBuddy not found at ${PLISTBUDDY}." >&2
    echo "   This script must be run on macOS." >&2
    exit 1
fi

PROFILE_DISPLAY_NAME="${CLIENT_NAME} ${WIFI_SSID} EAP-TLS"

echo "=============================================================================="
echo "  Apple Configuration Profile Generator (.mobileconfig)"
echo "=============================================================================="
echo "  Client Name     : ${CLIENT_NAME}"
echo "  SSID            : ${WIFI_SSID}"
echo "  RADIUS Server   : ${RADIUS_SERVER_NAME}"
echo "  Server CA       : ${SERVER_CA_PATH}"
echo "  Client P12      : ${CLIENT_P12_PATH}"
echo "  Profile Name    : ${PROFILE_DISPLAY_NAME}"
echo "  Identifier      : ${PROFILE_IDENTIFIER}"
echo "  Output          : ${OUTPUT_PATH}"
echo "  Force Overwrite : ${FORCE}"
echo ""
echo "  Security:"
echo "    Encryption    : WPA3-Enterprise (hard-coded)"
echo "    Auth Method   : EAP-TLS only (hard-coded)"
echo "    TLS Version   : 1.2 only"
echo "    P12 Password  : NOT embedded (user enters at install)"
echo "    Signing       : Unsigned"
echo "=============================================================================="

# ==============================================================================
# 2. Certificate Processing
# ==============================================================================

# Create a secure temporary directory for intermediate files
TMPDIR_WORK="$(mktemp -d)"
chmod 700 "${TMPDIR_WORK}"
trap 'rm -rf "${TMPDIR_WORK}"' EXIT INT TERM

# Verify the Server CA file is a valid X.509 certificate (supports PEM and DER)
if ! openssl x509 -in "${SERVER_CA_PATH}" -noout 2>/dev/null && \
   ! openssl x509 -inform der -in "${SERVER_CA_PATH}" -noout 2>/dev/null; then
    echo "❌ Error: Server CA file is not a valid X.509 certificate: ${SERVER_CA_PATH}" >&2
    exit 1
fi
echo "  ✔ Server CA certificate validated"

# Verify the P12 file is non-empty
if [ ! -s "${CLIENT_P12_PATH}" ]; then
    echo "❌ Error: Client P12 file is empty: ${CLIENT_P12_PATH}" >&2
    exit 1
fi
echo "  ✔ Client P12 bundle verified ($(wc -c < "${CLIENT_P12_PATH}" | tr -d ' ') bytes)"

# ==============================================================================
# 3. Deterministic UUID Generation
# ==============================================================================
# Generate UUIDs deterministically from content hashes so re-running the script
# with the same inputs produces identical output (idempotent).

generate_uuid_from_hash() {
    local input="$1"
    local hash
    hash=$(echo -n "${input}" | shasum -a 256 | cut -c1-32)
    # Format as UUID v4-style: 8-4-4-4-12
    echo "${hash:0:8}-${hash:8:4}-${hash:12:4}-${hash:16:4}-${hash:20:12}" | tr '[:lower:]' '[:upper:]'
}

# UUID for the Root CA payload (derived from certificate file content)
SERVER_CA_HASH=$(shasum -a 256 "${SERVER_CA_PATH}" | cut -c1-64)
UUID_ROOT_CA=$(generate_uuid_from_hash "root-ca:${SERVER_CA_HASH}")

# UUID for the PKCS#12 identity payload (derived from the P12 file content)
CLIENT_P12_HASH=$(shasum -a 256 "${CLIENT_P12_PATH}" | cut -c1-64)
UUID_CLIENT_IDENTITY=$(generate_uuid_from_hash "pkcs12:${CLIENT_P12_HASH}")

# UUID for the Wi-Fi payload (derived from SSID + client name combination)
UUID_WIFI=$(generate_uuid_from_hash "wifi:${WIFI_SSID}:${CLIENT_NAME}")

# UUID for the top-level Configuration profile
UUID_PROFILE=$(generate_uuid_from_hash "profile:${WIFI_SSID}:${CLIENT_NAME}:${SERVER_CA_HASH}")

echo ""
echo "  Generated UUIDs:"
echo "    Profile       : ${UUID_PROFILE}"
echo "    Root CA       : ${UUID_ROOT_CA}"
echo "    Client ID     : ${UUID_CLIENT_IDENTITY}"
echo "    Wi-Fi         : ${UUID_WIFI}"

# ==============================================================================
# 4. Build the Configuration Profile using PlistBuddy
# ==============================================================================
echo ""
echo "===> Building configuration profile..."

PLIST_FILE="${TMPDIR_WORK}/profile.plist"

# Start with an empty plist (PlistBuddy creates a new file if it doesn't exist)
# We build the entire structure through PlistBuddy Add/Import commands.

# --- Top-level profile keys ---
"${PLISTBUDDY}" -c "Add :PayloadDisplayName string '${PROFILE_DISPLAY_NAME}'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadIdentifier string '${PROFILE_IDENTIFIER}'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadType string Configuration" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadUUID string '${UUID_PROFILE}'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadVersion integer 1" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadDescription string 'Configures WPA3-Enterprise EAP-TLS for ${WIFI_SSID}'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadOrganization string 'Homelab'" "${PLIST_FILE}"

# --- PayloadContent array (holds the 3 sub-payloads) ---
"${PLISTBUDDY}" -c "Add :PayloadContent array" "${PLIST_FILE}"

# --------------------------------------------------------------------------
# Payload 0: Root CA Certificate (com.apple.security.root)
# --------------------------------------------------------------------------
"${PLISTBUDDY}" -c "Add :PayloadContent:0 dict" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:0:PayloadType string com.apple.security.root" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:0:PayloadVersion integer 1" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:0:PayloadIdentifier string '${PROFILE_IDENTIFIER}.root-ca'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:0:PayloadUUID string '${UUID_ROOT_CA}'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:0:PayloadDisplayName string 'RADIUS Server Root CA'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:0:PayloadDescription string 'Root CA for 802.1X RADIUS server authentication'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:0:PayloadCertificateFileName string '$(basename "${SERVER_CA_PATH}")'" "${PLIST_FILE}"

# Import the certificate as binary data — PlistBuddy's Import command
# reads the raw file bytes and stores them as a <data> field in the plist.
"${PLISTBUDDY}" -c "Import :PayloadContent:0:PayloadContent '${SERVER_CA_PATH}'" "${PLIST_FILE}"

# --------------------------------------------------------------------------
# Payload 1: Client Identity PKCS#12 (com.apple.security.pkcs12)
# --------------------------------------------------------------------------
"${PLISTBUDDY}" -c "Add :PayloadContent:1 dict" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:1:PayloadType string com.apple.security.pkcs12" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:1:PayloadVersion integer 1" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:1:PayloadIdentifier string '${PROFILE_IDENTIFIER}.client-identity'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:1:PayloadUUID string '${UUID_CLIENT_IDENTITY}'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:1:PayloadDisplayName string '${CLIENT_NAME} Client Identity'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:1:PayloadDescription string 'Client certificate and private key for EAP-TLS authentication'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:1:PayloadCertificateFileName string '$(basename "${CLIENT_P12_PATH}")'" "${PLIST_FILE}"

# Import the PKCS#12 file as binary data.
# NOTE: The Password key is intentionally omitted. The user will be prompted
# to enter the P12 password when installing the profile on their device.
# This is a deliberate security design decision — the password must be
# transmitted/received out-of-band.
"${PLISTBUDDY}" -c "Import :PayloadContent:1:PayloadContent '${CLIENT_P12_PATH}'" "${PLIST_FILE}"

# --------------------------------------------------------------------------
# Payload 2: Wi-Fi Configuration (com.apple.wifi.managed)
# --------------------------------------------------------------------------
"${PLISTBUDDY}" -c "Add :PayloadContent:2 dict" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:PayloadType string com.apple.wifi.managed" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:PayloadVersion integer 1" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:PayloadIdentifier string '${PROFILE_IDENTIFIER}.wifi'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:PayloadUUID string '${UUID_WIFI}'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:PayloadDisplayName string 'Wi-Fi (${WIFI_SSID})'" "${PLIST_FILE}"

# Network settings
"${PLISTBUDDY}" -c "Add :PayloadContent:2:SSID_STR string '${WIFI_SSID}'" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:HIDDEN_NETWORK bool false" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:AutoJoin bool true" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:ProxyType string None" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:CaptiveBypass bool true" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:DisableAssociationMACRandomization bool false" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:IsHotspot bool false" "${PLIST_FILE}"

# WPA3-Enterprise (hard-coded — non-configurable)
"${PLISTBUDDY}" -c "Add :PayloadContent:2:EncryptionType string WPA3" "${PLIST_FILE}"

# Client identity reference: points to the PKCS#12 payload UUID
"${PLISTBUDDY}" -c "Add :PayloadContent:2:PayloadCertificateUUID string '${UUID_CLIENT_IDENTITY}'" "${PLIST_FILE}"

# EAP Client Configuration (enterprise authentication settings)
"${PLISTBUDDY}" -c "Add :PayloadContent:2:EAPClientConfiguration dict" "${PLIST_FILE}"

# EAP-TLS only (type 13) — hard-coded, non-configurable
"${PLISTBUDDY}" -c "Add :PayloadContent:2:EAPClientConfiguration:AcceptEAPTypes array" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:EAPClientConfiguration:AcceptEAPTypes:0 integer 13" "${PLIST_FILE}"

# TLS 1.2 only (minimum and maximum pinned to 1.2) — hard-coded, CNSA requirement
"${PLISTBUDDY}" -c "Add :PayloadContent:2:EAPClientConfiguration:TLSMinimumVersion string 1.2" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:EAPClientConfiguration:TLSMaximumVersion string 1.2" "${PLIST_FILE}"

# Server trust anchors: reference the Root CA payload UUID
"${PLISTBUDDY}" -c "Add :PayloadContent:2:EAPClientConfiguration:PayloadCertificateAnchorUUID array" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:EAPClientConfiguration:PayloadCertificateAnchorUUID:0 string '${UUID_ROOT_CA}'" "${PLIST_FILE}"

# Trusted server names: only accept certificates with this CN
"${PLISTBUDDY}" -c "Add :PayloadContent:2:EAPClientConfiguration:TLSTrustedServerNames array" "${PLIST_FILE}"
"${PLISTBUDDY}" -c "Add :PayloadContent:2:EAPClientConfiguration:TLSTrustedServerNames:0 string '${RADIUS_SERVER_NAME}'" "${PLIST_FILE}"


# ==============================================================================
# 5. Finalize: Convert to XML and validate
# ==============================================================================
echo "===> Finalizing profile..."

# Convert to canonical XML plist format
plutil -convert xml1 "${PLIST_FILE}"

# Validate the plist is well-formed
if ! plutil -lint "${PLIST_FILE}" >/dev/null 2>&1; then
    echo "❌ Error: Generated plist failed validation." >&2
    echo "   This is a bug in the generator script." >&2
    exit 1
fi
echo "  ✔ Plist validation passed"

# Verify UUID cross-references
echo "  → Verifying UUID cross-references..."
ANCHOR_UUID_IN_WIFI=$("${PLISTBUDDY}" -c "Print :PayloadContent:2:EAPClientConfiguration:PayloadCertificateAnchorUUID:0" "${PLIST_FILE}")
ROOT_CA_UUID=$("${PLISTBUDDY}" -c "Print :PayloadContent:0:PayloadUUID" "${PLIST_FILE}")
if [ "${ANCHOR_UUID_IN_WIFI}" != "${ROOT_CA_UUID}" ]; then
    echo "❌ Error: PayloadCertificateAnchorUUID mismatch!" >&2
    echo "   Wi-Fi anchor: ${ANCHOR_UUID_IN_WIFI}" >&2
    echo "   Root CA UUID: ${ROOT_CA_UUID}" >&2
    exit 1
fi

CERT_UUID_IN_WIFI=$("${PLISTBUDDY}" -c "Print :PayloadContent:2:PayloadCertificateUUID" "${PLIST_FILE}")
IDENTITY_UUID=$("${PLISTBUDDY}" -c "Print :PayloadContent:1:PayloadUUID" "${PLIST_FILE}")
if [ "${CERT_UUID_IN_WIFI}" != "${IDENTITY_UUID}" ]; then
    echo "❌ Error: PayloadCertificateUUID mismatch!" >&2
    echo "   Wi-Fi cert:   ${CERT_UUID_IN_WIFI}" >&2
    echo "   Identity UUID: ${IDENTITY_UUID}" >&2
    exit 1
fi
echo "  ✔ UUID cross-references verified"

# Copy to final output location
mkdir -p "$(dirname "${OUTPUT_PATH}")"
cp "${PLIST_FILE}" "${OUTPUT_PATH}"
echo ""
echo "=============================================================================="
echo "✔ Configuration profile generated successfully!"
echo ""
echo "  Output: ${OUTPUT_PATH}"
echo "  Profile: ${PROFILE_DISPLAY_NAME}"
echo ""
echo "  To install on macOS:"
echo "    1. Transfer the .mobileconfig file to the target device"
echo "    2. Double-click the file to open System Settings → Profiles"
echo "    3. Review and approve the profile"
echo "    4. When prompted, enter the PKCS#12 password"
echo "       (the password is NOT embedded — it must be provided out-of-band)"
echo "=============================================================================="
