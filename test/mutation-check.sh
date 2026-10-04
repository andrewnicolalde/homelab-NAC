#!/usr/bin/env bash
# ==============================================================================
# Script: mutation-check.sh
# Purpose: Show that the functional tests in guarantees.sh really detect a
#          weakened TLS policy on the post-quantum server, rather than passing
#          for some unrelated reason.
#
# For each mutation below, the repository is copied to a temporary directory,
# one setting in the copy's k8s-pqc/config/eap is deliberately weakened, and
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

# name | sed expression applied to the copy's k8s-pqc/config/eap | tests (regex)
# The listed tests must FAIL, unless the list starts with "pass:", in which case
# they must still PASS: the mutation removes one of two redundant controls, so
# behaviour must not change (the static tests pin the setting itself).
MUTATIONS=(
    "no-cipher-suites|/^ *cipher_suites = /d|test_pqc_every_other_tls13_cipher_suite_is_rejected|test_both_tls_negotiation_below_policy_is_rejected"
    "chacha20-also-allowed|s/^( *cipher_suites = ).*/\1\"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\"/|test_pqc_every_other_tls13_cipher_suite_is_rejected"
    "aes128-preferred|s/^( *cipher_suites = ).*/\1\"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384\"/|test_pqc_client_offering_every_cipher_suite_gets_aes256|test_pqc_every_other_tls13_cipher_suite_is_rejected"
    # TLS 1.2 stays impossible: the hybrid ML-KEM groups exist only in TLS 1.3,
    # so a TLS 1.2 client and the server share no key exchange group
    "tls12-allowed-but-groups-pq-only|s/^( *tls_min_version = ).*/\1\"1.2\"/|pass:test_pqc_tls12_is_rejected"
    "tls12-allowed-with-classical-group|s/^( *tls_min_version = ).*/\1\"1.2\"/;s/^( *ecdh_curve = \")/\1secp384r1:/|test_pqc_tls12_is_rejected"
)

undetected=0
for m in "${MUTATIONS[@]}"; do
    name=${m%%|*}; rest=${m#*|}
    expr=${rest%%|*}; expected=${rest#*|}
    [ -n "${ONLY}" ] && ! [[ "${name}" =~ ${ONLY} ]] && continue

    copy=$(mktemp -d "${TMPDIR:-/tmp}/mutation.XXXXXX")
    rsync -a --exclude .git --exclude '*.tar.gz' "${REPO}/" "${copy}/"
    sed -E -i.orig "${expr}" "${copy}/k8s-pqc/config/eap"

    echo "=============================================================================="
    echo "Mutation: ${name}"
    diff "${copy}/k8s-pqc/config/eap.orig" "${copy}/k8s-pqc/config/eap" | sed -n 's/^[<>]/    &/p'
    if cmp -s "${copy}/k8s-pqc/config/eap.orig" "${copy}/k8s-pqc/config/eap"; then
        echo "  ✗ the mutation changed nothing; fix its sed expression"
        undetected=$((undetected + 1)); rm -rf "${copy}"; continue
    fi
    rm "${copy}/k8s-pqc/config/eap.orig"

    must=fail
    [[ "${expected}" == pass:* ]] && { must=pass; expected=${expected#pass:}; }
    out=$("${copy}/test/guarantees.sh" --only "${expected}" 2>&1)
    for t in $(echo "${expected}" | tr '|' ' '); do
        failed=false
        echo "${out}" | grep -qE "✗ pqc: ${t}\$" && failed=true
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
