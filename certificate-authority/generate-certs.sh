#!/usr/bin/env bash
# ==============================================================================
# Certificate Generation Script for 802.1X / EAP-TLS using Smallstep CLI (`step`)
# Configured for WPA3-Enterprise 192-bit (CNSA / Suite B) Mode (NIST P-384 / SHA-384)
# ==============================================================================
# You can execute this entire script or copy-paste each command individually
# into your shell to inspect the output at each step.
#
# Certificates created:
#   1. Root CA (root_ca.crt / root_ca.key) - valid 10 years (P-384)
#   2. FreeRADIUS Server Cert (server.crt / server.key) - valid 1 year (P-384)
#   3. UniFi AP Authenticator Cert (unifi-ap.crt / unifi-ap.key) - valid 1 year (P-384)
#   4. Client Identity Cert (client.crt / client.key) - valid 1 year (P-384)
#   5. Client PKCS#12 Bundle (client.p12) - for importing into macOS/iOS/Windows
# ==============================================================================

set -euo pipefail

# Move to the directory containing this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "Working directory: ${SCRIPT_DIR}"

# Elliptic Curve: WPA3-Enterprise 192-bit (CNSA) mandates NIST P-384 (ECDSA-SHA384)
CURVE="P-384"

# ------------------------------------------------------------------------------
# 1. Create the Root Certificate Authority (Root CA)
# ------------------------------------------------------------------------------
# - Profile 'root-ca' automatically configures X.509 v3 basicConstraints (CA:TRUE)
#   and appropriate keyCertSign/crlSign key usages.
# - Uses NIST P-384 curve with SHA-384.
# - '--not-after=87600h' sets validity to ~10 years.
# - '--no-password --insecure' creates the private key unencrypted.
# ------------------------------------------------------------------------------
if [ ! -f "root_ca.crt" ]; then
    echo "==> Creating Root CA (${CURVE})..."
    step certificate create "Homelab Root CA" root_ca.crt root_ca.key \
        --profile root-ca \
        --kty EC --curve "${CURVE}" \
        --not-after=87600h \
        --no-password --insecure
    echo "✔ Root CA created: root_ca.crt, root_ca.key"
else
    echo "==> Root CA already exists (root_ca.crt). Skipping."
fi

# ------------------------------------------------------------------------------
# 2. Create the FreeRADIUS Server Certificate
# ------------------------------------------------------------------------------
# - Used by FreeRADIUS for EAP-TLS (authenticating to Wi-Fi/switch supplicants)
#   and RADSec (TLS encryption between APs and FreeRADIUS).
# - Profile 'leaf' signs this certificate using the Root CA and sets serverAuth.
# ------------------------------------------------------------------------------
RADIUS_IP="10.50.0.100"

# Optional additional Subject Alternative Names (SANs)
# Add any extra hostnames or FQDNs here if you decide to enable them in the future.
# Leave empty () so that ONLY the RADIUS_IP is valid for the server certificate.
ADDITIONAL_SANS=(
    # "radius.homelab.lan"
    # "radius.local"
)

# Build SAN arguments: always include RADIUS_IP, plus any optional SANs
SERVER_SAN_ARGS=(--san "${RADIUS_IP}")
if [ "${#ADDITIONAL_SANS[@]}" -gt 0 ]; then
    for san in "${ADDITIONAL_SANS[@]}"; do
        SERVER_SAN_ARGS+=(--san "${san}")
    done
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

# In addition, Alpine's default FreeRADIUS eap module expects server.pem
# (cert + private key combined) and ca.pem in /etc/raddb/certs/.
if [ ! -f "server.pem" ] && [ -f "server.crt" ] && [ -f "server.key" ]; then
    cat server.crt server.key > server.pem
    chmod 600 server.pem
    echo "✔ Created combined server.pem for Alpine FreeRADIUS"
fi
if [ ! -f "ca.pem" ] && [ -f "root_ca.crt" ]; then
    cp root_ca.crt ca.pem
    echo "✔ Created ca.pem from root_ca.crt"
fi

# ------------------------------------------------------------------------------
# 3. Create the UniFi APs Authenticator Certificate (for RADSec)
# ------------------------------------------------------------------------------
# - UniFi Network (v8.4+) uses mutual TLS (mTLS) for RADSec over TCP 2083.
# - The UniFi controller pushes this certificate and key down to your APs so
#   they can authenticate themselves to FreeRADIUS as trusted authenticators.
# - You only need ONE authenticator cert/key bundle uploaded to your UniFi
#   RADIUS profile (it is shared across your APs).
# - Requires 'clientAuth' (Client Authentication EKU).
# ------------------------------------------------------------------------------
AP_IDENTITY="unifi-aps"

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

# ------------------------------------------------------------------------------
# 4. Create a Test Client Certificate (Supplicant / Device)
# ------------------------------------------------------------------------------
# - Used by your test client device (e.g., MacBook, iPhone, test laptop).
# - Subject name can be a user or device identifier (e.g. 'andrew-laptop').
# - In FreeRADIUS, this identity will be available to authorize the connection
#   and optionally assign a dynamic VLAN ID.
# ------------------------------------------------------------------------------
CLIENT_IDENTITY="client-device-01"

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

# ------------------------------------------------------------------------------
# 5. Package Client Cert into a PKCS#12 (.p12) Bundle
# ------------------------------------------------------------------------------
# - macOS, iOS, Android, and Windows require client certificates in PKCS#12
#   format (.p12 / .pfx) containing the client cert, private key, and root CA.
# - This command bundles root_ca.crt so the device trusts the entire chain.
# - Note: You will be prompted to set an export password for the .p12 archive.
# ------------------------------------------------------------------------------
if [ ! -f "client.p12" ]; then
    echo "==> Packaging client certificate into client.p12 (enter an export password when prompted)..."
    step certificate p12 client.p12 client.crt client.key \
        --ca root_ca.crt
    echo "✔ PKCS#12 bundle created: client.p12"
else
    echo "==> Client PKCS#12 bundle already exists (client.p12). Skipping."
fi

echo ""
echo "=============================================================================="
echo "All certificates successfully generated in ${SCRIPT_DIR}:"
echo "  - root_ca.crt / root_ca.key   : Root Certificate Authority"
echo "  - server.crt / server.key     : FreeRADIUS Server Certificate (EAP-TLS & RADSec)"
echo "  - unifi-ap.crt / unifi-ap.key : UniFi AP Authenticator Client Cert (RADSec)"
echo "  - client.crt / client.key     : End-user Client Identity Cert (EAP-TLS)"
echo "  - client.p12                  : PKCS#12 bundle for client import"
echo "=============================================================================="
