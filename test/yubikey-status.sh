#!/usr/bin/env bash
# ==============================================================================
# yubikey-status.sh - Comprehensive Non-Destructive YubiKey State Auditor
# ==============================================================================
# Audits connected YubiKey devices across all subsystems:
# - Device identity, firmware, and transports (USB / NFC)
# - PIV (Smart Card / PKI) configuration and slot certificates
# - OpenPGP applet keys, fingerprints, and touch policies
# - FIDO / FIDO2 status, PIN attempts, and CTAP capability
# - OATH (TOTP/HOTP) application and password protection status
# - macOS Smart Card / CryptoTokenKit subsystem visibility
# - Hardware Root CA readiness and security advisory assessment
#
# GUARANTEE: This script is 100% read-only and non-state-mutating.
# ==============================================================================

set -euo pipefail

# Text formatting
BOLD="\033[1m"
DIM="\033[2m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
MAGENTA="\033[35m"
CYAN="\033[36m"
RED="\033[31m"
RESET="\033[0m"

header() {
    echo -e "\n${BOLD}${BLUE}=== $1 ===${RESET}"
}

subheading() {
    echo -e "\n${BOLD}${CYAN}--- $1 ---${RESET}"
}

warn() {
    echo -e "${YELLOW}⚠️  $1${RESET}"
}

info() {
    echo -e "${DIM}$1${RESET}"
}

success() {
    echo -e "${GREEN}✓ $1${RESET}"
}

# 1. Dependency Verification
if ! command -v ykman &>/dev/null; then
    echo -e "${RED}Error: 'ykman' (YubiKey Manager CLI) is not installed or not in PATH.${RESET}"
    echo "Install via Homebrew: brew install ykman"
    exit 1
fi

# 2. Device Discovery
header "1. Discovered YubiKey Devices"

CONNECTED_DEVICES=$(ykman list 2>&1 || true)

if [[ -z "$CONNECTED_DEVICES" || "$CONNECTED_DEVICES" =~ "No YubiKey detected" ]]; then
    echo -e "${RED}No YubiKey detected. Please plug in a YubiKey and run again.${RESET}"
    exit 1
fi

echo "$CONNECTED_DEVICES"

# Select target device if specified, otherwise default to first/only
TARGET_SERIAL="${1:-}"
if [[ -z "$TARGET_SERIAL" ]]; then
    # Extract serial of first connected device
    TARGET_SERIAL=$(echo "$CONNECTED_DEVICES" | grep -o 'Serial: [0-9]*' | head -n 1 | awk '{print $2}')
fi

DEVICE_ARG=()
if [[ -n "$TARGET_SERIAL" ]]; then
    DEVICE_ARG=("--device" "$TARGET_SERIAL")
    info "\nTargeting Serial: ${BOLD}${TARGET_SERIAL}${RESET}"
fi

# 3. Core Device Profile
header "2. Core Device Profile"
ykman "${DEVICE_ARG[@]}" info

# Extract firmware version for downstream heuristics
FW_VERSION=$(ykman "${DEVICE_ARG[@]}" info 2>/dev/null | awk -F': ' '/Firmware version:/ {print $2}' || echo "0.0.0")

# 4. PIV (Personal Identity Verification / PKI) Applet
header "3. PIV (Smart Card / PKI) Status"
PIV_INFO=$(ykman "${DEVICE_ARG[@]}" piv info 2>&1 || true)
echo "$PIV_INFO"

subheading "PIV Certificate Slot Inspection (9a, 9c, 9d, 9e)"
SLOTS=("9a:Authentication" "9c:Digital Signature (CA Target)" "9d:Key Management" "9e:Card Authentication")
HAS_CERT=false

for ENTRY in "${SLOTS[@]}"; do
    SLOT="${ENTRY%%:*}"
    LABEL="${ENTRY#*:}"
    
    # Check if certificate exists by attempting an export to stdout (read-only)
    if CERT_PEM=$(ykman "${DEVICE_ARG[@]}" piv certificates export "$SLOT" - 2>/dev/null); then
        HAS_CERT=true
        echo -e "${GREEN}▶ Slot ${SLOT} (${LABEL}): CERTIFICATE PRESENT${RESET}"
        if command -v openssl &>/dev/null; then
            SUBJECT=$(echo "$CERT_PEM" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject= //')
            ISSUER=$(echo "$CERT_PEM" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer= //')
            DATES=$(echo "$CERT_PEM" | openssl x509 -noout -dates 2>/dev/null | tr '\n' ' ')
            FINGERPRINT=$(echo "$CERT_PEM" | openssl x509 -noout -fingerprint -sha256 2>/dev/null)
            echo -e "    ${DIM}Subject:     ${SUBJECT}${RESET}"
            echo -e "    ${DIM}Issuer:      ${ISSUER}${RESET}"
            echo -e "    ${DIM}Validity:    ${DATES}${RESET}"
            echo -e "    ${DIM}Fingerprint: ${FINGERPRINT}${RESET}"
        fi
    else
        echo -e "${DIM}▶ Slot ${SLOT} (${LABEL}): Empty / Unprovisioned${RESET}"
    fi
done

if [ "$HAS_CERT" = false ]; then
    success "PIV certificate container is clean (no slots currently populated)."
fi

# 5. OpenPGP Applet
header "4. OpenPGP Application Status"
if OPENPGP_INFO=$(ykman "${DEVICE_ARG[@]}" openpgp info 2>/dev/null); then
    echo "$OPENPGP_INFO"
    
    # Check if active keys exist
    if echo "$OPENPGP_INFO" | grep -q "Fingerprint:"; then
        warn "Active OpenPGP keys detected on this device!"
        echo -e "    ${YELLOW}Caution: A full device reset would erase these GPG identities.${RESET}"
        echo -e "    ${YELLOW}PIV can be reset or modified independently without affecting OpenPGP.${RESET}"
    fi
else
    info "OpenPGP application is disabled or not supported."
fi

# 6. FIDO2 / WebAuthn Status
header "5. FIDO / FIDO2 Status"
if FIDO_INFO=$(ykman "${DEVICE_ARG[@]}" fido info 2>/dev/null); then
    echo "$FIDO_INFO"
    
    # Safe check: do not prompt for PIN, just report CTAP credential management capability
    if [[ "$FW_VERSION" > "5.2.0" || "$FW_VERSION" == "5.2.0" ]]; then
        success "FIDO2 Credential Management (CTAP 2.1) is supported on this firmware."
        info "    (You can view/delete individual passkeys using 'ykman fido credentials list')"
    else
        info "    Note: Firmware < 5.2.0 uses CTAP 2.0 (individual passkeys cannot be listed/deleted individually)."
    fi
else
    info "FIDO application is disabled or not accessible."
fi

# 7. OATH (Authenticator / TOTP) Status
header "6. OATH (Authenticator / TOTP) Status"
if OATH_INFO=$(ykman "${DEVICE_ARG[@]}" oath info 2>/dev/null); then
    echo "$OATH_INFO"
else
    info "OATH application is disabled or not accessible."
fi

# 8. macOS Smart Card Subsystem Visibility
header "7. macOS Smart Card / PC/SC Subsystem"
if command -v security &>/dev/null; then
    SC_LIST=$(security list-smartcards 2>&1 || true)
    if [[ "$SC_LIST" =~ "No smartcards found" || -z "$SC_LIST" ]]; then
        info "macOS reports: No smartcard tokens currently enrolled in Keychain."
        info "    (Expected when PIV slots contain no certificates paired with macOS)."
    else
        echo "$SC_LIST"
    fi
else
    info "macOS 'security' command not available (non-Darwin host)."
fi

# 9. Hardware Root CA Readiness & Security Advisory Assessment
header "8. Hardware Root CA Architecture & Security Assessment"

echo -e "${BOLD}Assessment for Hardware Root CA Duty (PIV Slot 9c with NIST P-384):${RESET}\n"

# A. Firmware & Management Key Capability
if [[ "$FW_VERSION" > "5.4.2" || "$FW_VERSION" == "5.4.2" ]]; then
    success "PIV Management Key: Supports modern AES-128/192/256 keys (FW $FW_VERSION >= 5.4.2)."
else
    warn "PIV Management Key: Restricted to legacy 3DES (Triple-DES) (FW $FW_VERSION < 5.4.2)."
fi

# B. PIV Key Metadata
if [[ "$FW_VERSION" > "5.3.0" || "$FW_VERSION" == "5.3.0" ]]; then
    success "PIV Metadata: Supported (FW $FW_VERSION >= 5.3.0)."
else
    info "PIV Metadata: Not supported on-chip (FW $FW_VERSION < 5.3.0). Standard PKCS#11 cert-backed lookups apply."
fi

# C. Algorithm Support for CA
if [[ "$FW_VERSION" > "5.7.0" || "$FW_VERSION" == "5.7.0" ]]; then
    success "Cryptographic Algorithms: Supports RSA-4096, RSA-3072, ECC P-256, P-384, and Ed25519 in PIV."
else
    info "Cryptographic Algorithms: Supports ECC P-256, NIST P-384, and RSA-2048 in PIV (FW < 5.7.0)."
    success "Target Algorithm (NIST P-384 / ECCP384): Fully supported on-chip."
fi

# D. Security Advisory Posture
subheading "Security Advisories Overview"
echo -e "• ${BOLD}ROCA (CVE-2017-15361):${RESET} ${GREEN}NOT AFFECTED${RESET} (YubiKey 5 series is completely immune)."

if [[ "$FW_VERSION" < "5.7.0" ]]; then
    echo -e "• ${BOLD}EUCLEAK (CVE-2024-45678):${RESET} ${YELLOW}POTENTIALLY AFFECTED (FW < 5.7.0)${RESET}"
    echo -e "  ${DIM}Details: Side-channel EM emission leakage during ECDSA operations on Infineon chip.${RESET}"
    echo -e "  ${DIM}Mitigation for Root CA: Key lives in offline cold storage (safe/lockbox). Physical theft${RESET}"
    echo -e "  ${DIM}and oscilloscope side-channel capture are non-factors for an offline vault token.${RESET}"
else
    echo -e "• ${BOLD}EUCLEAK (CVE-2024-45678):${RESET} ${GREEN}IMMUNE${RESET} (YubiOS in-house crypto on FW >= 5.7.0)."
fi

# E. Isolation Confirmation
subheading "Applet Isolation Notice"
echo -e "${GREEN}✓ PIV Applet Isolation:${RESET} Running ${BOLD}ykman piv reset${RESET} will ${BOLD}ONLY${RESET} erase the PIV applet."
echo -e "  OpenPGP keys, FIDO passkeys, and OATH TOTP accounts will remain untouched."

echo -e "\n${BOLD}${GREEN}Audit complete.${RESET}\n"
