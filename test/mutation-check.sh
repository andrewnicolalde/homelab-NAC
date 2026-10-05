#!/usr/bin/env bash
# ==============================================================================
# Script: mutation-check.sh
# Purpose: Show that the functional tests in guarantees.sh really detect a
#          weakened TLS policy on either server, rather than passing
#          for some unrelated reason.
#
# For each mutation below, the repository is copied to a temporary directory,
# one setting in the copy's eap configuration is deliberately weakened, and
# the relevant tests are run against the copy. Every test listed for that
# mutation must FAIL; if one passes, it does not guard that setting.
# The working tree is never modified.
#
# Requirements: the same as the functional tests in guarantees.sh.
# Usage: ./test/mutation-check.sh [--only <mutation-name-regex>]
# Exit status is the number of mutations that went undetected.
# ==============================================================================
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ONLY=""
case "${1:-}" in
    --only) ONLY=$2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
esac

# name | file in the copy | sed expression applied to it | tests (regex)
# The listed tests must FAIL, unless the list starts with "pass:", in which case
# they must still PASS: the mutation removes one of two redundant controls, so
# behaviour must not change (the static tests pin the setting itself).
MUTATIONS=(
    "no-cipher-suites|k8s-pqc/config/eap|/^ *cipher_suites = /d|test_pqc_every_other_tls13_cipher_suite_is_rejected|test_both_tls_negotiation_below_policy_is_rejected"
    "chacha20-also-allowed|k8s-pqc/config/eap|s/^( *cipher_suites = ).*/\1\"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\"/|test_pqc_every_other_tls13_cipher_suite_is_rejected"
    # AES-128 suites are refused by cipher_suites and by @SECLEVEL=4 (they
    # offer 128 bits); ChaCha20 (256-bit key) is refused by cipher_suites only
    "aes128-preferred|k8s-pqc/config/eap|s/^( *cipher_suites = ).*/\1\"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384\"/|pass:test_pqc_every_other_tls13_cipher_suite_is_rejected"
    "aes128-preferred-no-seclevel|k8s-pqc/config/eap|s/^( *cipher_suites = ).*/\1\"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384\"/;s/:@SECLEVEL=4//|test_pqc_client_offering_every_cipher_suite_gets_aes256|test_pqc_every_other_tls13_cipher_suite_is_rejected"
    # TLS 1.2 stays impossible: the hybrid ML-KEM groups exist only in TLS 1.3,
    # so a TLS 1.2 client and the server share no key exchange group
    "tls12-allowed-but-groups-pq-only|k8s-pqc/config/eap|s/^( *tls_min_version = ).*/\1\"1.2\"/|pass:test_pqc_tls12_is_rejected"
    # @SECLEVEL=4 is the only control on the signatures *on* certificates
    "no-seclevel-pqc|k8s-pqc/config/eap|s/:@SECLEVEL=4//|test_both_client_certificate_signed_with_sha256_is_rejected"
    "no-seclevel-classical|k8s/config/eap|s/:@SECLEVEL=4//|test_both_client_certificate_signed_with_sha256_is_rejected"
    # Device keys on other curves (P-256) are refused by two controls on each
    # server: @SECLEVEL=4 on both, plus sigalgs_list on the PQC server (TLS 1.3
    # signature schemes name the curve) and ecdh_curve on the classical server
    # (TLS 1.2 checks certificate keys against the group list; its signature
    # algorithms do not name the curve). Either one alone must still hold.
    "no-sigalgs-pqc|k8s-pqc/config/eap|/^ *sigalgs_list = /d|pass:test_both_client_signature_other_than_p384_is_rejected"
    "no-sigalgs-or-seclevel-pqc|k8s-pqc/config/eap|/^ *sigalgs_list = /d;s/:@SECLEVEL=4//|test_both_client_signature_other_than_p384_is_rejected"
    "p256-curve-classical|k8s/config/eap|s/^( *ecdh_curve = \")secp384r1/\1secp384r1:prime256v1/|pass:test_both_client_signature_other_than_p384_is_rejected"
    "p256-curve-no-seclevel-classical|k8s/config/eap|s/^( *ecdh_curve = \")secp384r1/\1secp384r1:prime256v1/;s/:@SECLEVEL=4//|test_both_client_signature_other_than_p384_is_rejected"
    # SHA-256 handshake signatures (TLS 1.2) are refused by sigalgs_list and
    # by @SECLEVEL=4
    "no-sigalgs-classical|k8s/config/eap|/^ *sigalgs_list = /d|pass:test_classical_client_signature_with_sha256_is_rejected"
    "no-sigalgs-or-seclevel-classical|k8s/config/eap|/^ *sigalgs_list = /d;s/:@SECLEVEL=4//|test_classical_client_signature_with_sha256_is_rejected"
    # A leading SUITEB192 in cipher_list switches OpenSSL to Suite B mode,
    # which overrides ecdh_curve with P-384 (in TLS 1.3 too) and discards the
    # rest of the string, @SECLEVEL=4 included
    "suiteb192-pqc|k8s-pqc/config/eap|s/^( *cipher_list = \")[^:]*/\1SUITEB192/|test_pqc_every_classical_key_exchange_group_is_rejected|test_pqc_accepts_each_hybrid_group"
    # RadSec listener (k8s/config/radsec): each control weakened in turn
    "radsec-tls12-allowed|k8s/config/radsec|s/^( *tls_min_version = )\"1\.3\"/\1\"1.2\"/|test_both_radsec_tls12_is_rejected"
    "radsec-chacha20-allowed|k8s/config/radsec|s/^( *cipher_suites = ).*/\1\"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\"/|test_both_radsec_non_cnsa_cipher_suites_are_rejected"
    "radsec-mlkem-allowed|k8s/config/radsec|s/^( *ecdh_curve = ).*/\1\"secp384r1:X25519MLKEM768\"/|test_both_radsec_non_cnsa_groups_are_rejected"
    "radsec-no-seclevel|k8s/config/radsec|s/:@SECLEVEL=4//|test_both_radsec_client_certificate_signed_with_sha256_is_rejected"
    "radsec-no-client-cert-required|k8s/config/radsec|s/^( *require_client_cert = )yes/\1no/|test_both_radsec_requires_a_client_certificate"
    # P-256 AP keys are refused by sigalgs_list and by @SECLEVEL=4
    "radsec-no-sigalgs|k8s/config/radsec|/^ *sigalgs_list = /d|pass:test_both_radsec_client_signature_other_than_p384_is_rejected"
    "radsec-no-sigalgs-or-seclevel|k8s/config/radsec|/^ *sigalgs_list = /d;s/:@SECLEVEL=4//|test_both_radsec_client_signature_other_than_p384_is_rejected"
    # Device certificates are refused by the trust anchor and by the issuer pin
    "radsec-trusts-device-ca|k8s/config/radsec|s#^( *ca_file = /etc/raddb/certs/)authenticators-ca\.pem#\1ca.pem#|pass:test_both_radsec_refuses_device_certificates"
    "radsec-trusts-device-ca-without-issuer-pin|k8s/config/radsec|s#^( *ca_file = /etc/raddb/certs/)authenticators-ca\.pem#\1ca.pem#;/^ *check_cert_issuer = /d|test_both_radsec_refuses_device_certificates"
    # The radsec client list admits every source address
    "radsec-any-client-address|k8s/config/clients.conf.example|/^clients radsec/,/^}/ s#ipaddr = 10\.1\.0\.0/24#ipaddr = 0.0.0.0/0#|test_both_radsec_refuses_connections_from_unlisted_addresses"
    # The plaintext warning must fire over UDP, and only over UDP
    "no-plaintext-warning|k8s/config/check-eap-tls|/^ *cert_log_plaintext$/d|test_both_plaintext_radius_is_logged_as_a_warning"
    "plaintext-warning-also-over-radsec|k8s/config/check-eap-tls|s/!= \"2083\"/!= \"0\"/|test_both_plaintext_radius_is_logged_as_a_warning"
    # Without the Called-Station-Id split, cert_log has no SSID to record
    "no-ssid-split|k8s/config/check-eap-tls|/^ *rewrite_called_station_id$/d|test_both_cert_log_records_the_ssid"
    "tls12-allowed-with-classical-group|k8s-pqc/config/eap|s/^( *tls_min_version = ).*/\1\"1.2\"/;s/^( *ecdh_curve = \")/\1secp384r1:/|test_pqc_tls12_is_rejected"
)

undetected=0
for m in "${MUTATIONS[@]}"; do
    name=${m%%|*}; rest=${m#*|}
    file=${rest%%|*}; rest=${rest#*|}
    expr=${rest%%|*}; expected=${rest#*|}
    [ -n "${ONLY}" ] && ! [[ "${name}" =~ ${ONLY} ]] && continue

    copy=$(mktemp -d "${TMPDIR:-/tmp}/mutation.XXXXXX")
    rsync -a --exclude .git --exclude '*.tar.gz' "${REPO}/" "${copy}/"
    sed -E -i.orig "${expr}" "${copy}/${file}"

    echo "=============================================================================="
    echo "Mutation: ${name} (${file})"
    diff "${copy}/${file}.orig" "${copy}/${file}" | sed -n 's/^[<>]/    &/p'
    if cmp -s "${copy}/${file}.orig" "${copy}/${file}"; then
        echo "  ✗ the mutation changed nothing; fix its sed expression"
        undetected=$((undetected + 1)); rm -rf "${copy}"; continue
    fi
    rm "${copy}/${file}.orig"

    must=fail
    [[ "${expected}" == pass:* ]] && { must=pass; expected=${expected#pass:}; }
    out=$("${copy}/test/guarantees.sh" --only "${expected}" 2>&1)
    for t in $(echo "${expected}" | tr '|' ' '); do
        failed=false
        echo "${out}" | grep -qE "✗ (classical|pqc): ${t}\$" && failed=true
        if [ "${must}" = fail ] && [ "${failed}" = true ]; then
            echo "  ✔ detected by ${t}"
        elif [ "${must}" = pass ] && [ "${failed}" = false ] && echo "${out}" | grep -qE "^  ${t}\$"; then
            echo "  ✔ ${t} still passes: the redundant control holds"
        else
            echo "  ✗ unexpected result from ${t} (expected it to ${must})"
            undetected=$((undetected + 1))
        fi
    done
    rm -rf "${copy}"
done

echo "=============================================================================="
[ "${undetected}" -eq 0 ] && echo "  Every mutation was detected" || echo "  ${undetected} expected detection(s) missing"
echo "=============================================================================="
exit "${undetected}"
