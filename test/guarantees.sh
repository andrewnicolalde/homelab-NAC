#!/usr/bin/env bash
# ==============================================================================
# Script: guarantees.sh
# Purpose: Unit-test-style checks that every guarantee of the EAP-TLS setup
#          holds, for both the classical and the post-quantum deployment
# ==============================================================================
# Each test_* function checks one guarantee and is named after it.
#
#   test_static_*   Read the repository's configuration and manifests. Fast,
#                   need nothing but bash, sed and awk.
#   test_image_*    Inspect the FreeRADIUS image pinned in the Deployment.
#   test_both_*     Functional: run against each server in a disposable lab.
#   test_classical_*, test_pqc_*
#                   Functional: run against one server only.
#
# The functional lab runs the pinned FreeRADIUS image with the repository's
# own eap, check-eap-tls, cert_vlan, cert_log and clients.conf.example,
# the radiusd arguments from the Deployment, and a throwaway
# PKI generated per run. Lab authorize: client-device-01 -> VLAN 10,
# client-device-02 -> VLAN 30.
#
# Private configuration can be checked too: set PRIVATE_CONFIG_DIR to the
# overlay directory to run the static checks against its clients.conf,
# authorize and kustomization.yaml as well.
#
# Requirements for the functional tests: podman or docker, and the eapol_test
# image built from test/Dockerfile with OpenSSL >= 3.5 and RadSec support
# (CONFIG_RADIUS_TLS, set in the Dockerfile):
#   podman build --build-arg ALPINE_VERSION=3.24.1 -t eapol-test:pqc -f test/Dockerfile test
#
# Usage: ./test/guarantees.sh [--static] [--only <regex>] [--keep]
#   --static      Run only the static tests
#   --only        Run only tests whose name matches the regex
#   --keep        Keep the work directory (lab PKI, client output, server logs)
#   RADIUS_IMAGE  FreeRADIUS image (default: the digest pinned in the Deployment)
#   EAPOL_IMAGE   eapol_test image (default: eapol-test:pqc)
# Exit status is the number of failed tests (0 = every guarantee holds).
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${SCRIPT_DIR}/.." && pwd)"

STATIC_ONLY=false
ONLY=""
KEEP=false
while [ $# -gt 0 ]; do
    case "$1" in
        --static) STATIC_ONLY=true; shift ;;
        --only) ONLY="$2"; shift 2 ;;
        --keep) KEEP=true; shift ;;
        -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

# Repository files under test
EAP_CLASSICAL="${REPO}/k8s/config/eap"
EAP_PQC="${REPO}/k8s-pqc/config/eap"
CHECK_EAP_TLS="${REPO}/k8s/config/check-eap-tls"
RADIUSD_CONF="${REPO}/k8s/config/radiusd.conf"
KUSTOMIZE_BASE="${REPO}/k8s/kustomization.yaml"
KUSTOMIZE_PQC="${REPO}/k8s-pqc/kustomization.yaml"
CERT_VLAN="${REPO}/k8s/config/cert_vlan"
CERT_LOG="${REPO}/k8s/config/cert_log"
RADSEC_SITE="${REPO}/k8s/config/radsec"
DEPLOY_CLASSICAL="${REPO}/k8s/01-deployment-test.yaml"
DEPLOY_PQC="${REPO}/k8s-pqc/01-deployment-pqc.yaml"
DOCKERFILE="${REPO}/docker/Dockerfile"
# Every TLS 1.3 cipher suite (RFC 8446 and OpenSSL)
TLS13_SUITES=(TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256 TLS_CHACHA20_POLY1305_SHA256
              TLS_AES_128_CCM_SHA256 TLS_AES_128_CCM_8_SHA256)
# Every classical (non-hybrid) elliptic-curve key exchange group in TLS 1.3
CLASSICAL_GROUPS=(X25519 X448 P-256 P-384 P-521)
CLIENTS_FILES=("${REPO}/k8s/config/clients.conf.example")
AUTHORIZE_FILES=("${REPO}/k8s/config/authorize.example")
OVERLAY_FILES=("${REPO}/examples/private-overlay/kustomization.yaml.example")
if [ -n "${PRIVATE_CONFIG_DIR:-}" ]; then
    [ -f "${PRIVATE_CONFIG_DIR}/clients.conf" ] && CLIENTS_FILES+=("${PRIVATE_CONFIG_DIR}/clients.conf")
    [ -f "${PRIVATE_CONFIG_DIR}/authorize" ] && AUTHORIZE_FILES+=("${PRIVATE_CONFIG_DIR}/authorize")
    [ -f "${PRIVATE_CONFIG_DIR}/kustomization.yaml" ] && OVERLAY_FILES+=("${PRIVATE_CONFIG_DIR}/kustomization.yaml")
fi

# ==============================================================================
# Test framework
# ==============================================================================
PASSED=0; FAILED=0; SKIPPED=0; FAILED_NAMES=()
CURRENT_FAILS=0

fail() { CURRENT_FAILS=$((CURRENT_FAILS + 1)); printf '      ✗ %s\n' "$*"; }
skip() { CURRENT_FAILS=-1; printf '      - skipped: %s\n' "$*"; }

expect_eq() { # actual expected message
    [ "$1" = "$2" ] || fail "$3 (expected '$2', got '$1')"
}
expect_match() { # file extended-regex message
    grep -Eq -- "$2" "$1" || fail "$3 [$(basename "$1")]"
}
expect_no_match() { # file extended-regex message
    local hit
    hit=$(grep -En -- "$2" "$1" | head -n1)
    [ -z "${hit}" ] || fail "$3 [$(basename "$1"):${hit%%:*}]"
}

# Contents of a named section, e.g. section_body file "tls-config tls-common"
section_body() {
    awk -v start="$2" '
        index($0, start " {") && !depth { depth = 1; next }
        depth {
            line = $0; sub(/#.*/, "", line)
            opens = gsub(/\{/, "{", line); closes = gsub(/\}/, "}", line)
            depth += opens - closes
            if (depth <= 0) exit
            print
        }' "$1"
}
# Value of "key = value" in config text on stdin, without quotes
conf_value() { sed -nE "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"?([^\"#]*[^\"#[:space:]])\"?.*/\1/p" | head -n1; }

run_test() {
    local name=$1
    if [ -n "${ONLY}" ] && ! [[ "${name}" =~ ${ONLY} ]]; then return; fi
    CURRENT_FAILS=0
    printf '  %s\n' "${name}"
    "${name}"
    if [ "${CURRENT_FAILS}" -eq 0 ]; then
        PASSED=$((PASSED + 1)); printf '      ✔ pass\n'
    elif [ "${CURRENT_FAILS}" -lt 0 ]; then
        SKIPPED=$((SKIPPED + 1))
    else
        FAILED=$((FAILED + 1)); FAILED_NAMES+=("${MODE:+${MODE}: }${name}")
    fi
}
run_group() { # function-name prefix
    local t
    for t in $(declare -F | awk '{print $3}' | grep -E "^$1"); do run_test "${t}"; done
}

# ==============================================================================
# Static tests: configuration and manifests
# ==============================================================================

# --- Admission policy ---------------------------------------------------------

test_static_admission_policy_runs_after_certificate_verification_on_both_servers() {
    local f
    for f in "${EAP_CLASSICAL}" "${EAP_PQC}"; do
        expect_eq "$(section_body "$f" "    tls" | conf_value virtual_server)" "check-eap-tls" \
            "eap tls {} must call the check-eap-tls virtual server ($(basename "$(dirname "$(dirname "$f")")"))"
    done
}

test_static_both_deployments_mount_the_shared_policy_read_only() {
    local f path
    for f in "${DEPLOY_CLASSICAL}" "${DEPLOY_PQC}"; do
        for path in /etc/raddb/radiusd.conf /etc/raddb/sites-enabled/check-eap-tls /etc/raddb/mods-enabled/cert_vlan /etc/raddb/mods-enabled/cert_log; do
            awk -v p="${path}" '$0 ~ "mountPath: " p "$" {found = 1; getline; getline; if ($0 ~ /readOnly: true/) ok = 1}
                END {exit !(found && ok)}' "$f" || fail "$(basename "$f") must mount ${path} read-only"
        done
    done
}

test_static_policy_discards_claim_derived_vlan_before_lookup() {
    local body
    body=$(section_body "${CHECK_EAP_TLS}" "server check-eap-tls")
    local attr
    for attr in Tunnel-Type Tunnel-Medium-Type Tunnel-Private-Group-Id; do
        echo "${body}" | grep -Eq "&${attr} !\* ANY" || fail "check-eap-tls must delete ${attr} from outer.reply"
    done
    # The deletions must come before the certificate lookup
    local del_line lookup_line
    del_line=$(echo "${body}" | grep -nE '!\* ANY' | head -n1 | cut -d: -f1)
    lookup_line=$(echo "${body}" | grep -nE '^[[:space:]]*cert_vlan[[:space:]]*$' | head -n1 | cut -d: -f1)
    [ -n "${del_line}" ] && [ -n "${lookup_line}" ] && [ "${del_line}" -lt "${lookup_line}" ] \
        || fail "VLAN attributes must be deleted before cert_vlan runs"
}

test_static_policy_accepts_only_when_certificate_lookup_matched() {
    local body accepts in_ok
    body=$(section_body "${CHECK_EAP_TLS}" "server check-eap-tls")
    accepts=$(echo "${body}" | grep -cE 'Auth-Type[[:space:]]*:=[[:space:]]*Accept')
    expect_eq "${accepts}" "1" "exactly one Auth-Type := Accept in check-eap-tls"
    in_ok=$(echo "${body}" | awk '
        /if \(ok\)/ { inside = 1; depth = 0 }
        inside { line = $0; depth += gsub(/\{/, "{", line) - gsub(/\}/, "}", line)
                 if ($0 ~ /Auth-Type[[:space:]]*:=[[:space:]]*Accept/) found = 1
                 if (depth <= 0 && $0 ~ /\}/) inside = 0 }
        END { print found + 0 }')
    expect_eq "${in_ok}" "1" "Auth-Type := Accept must be set only inside if (ok) after cert_vlan"
}

test_static_certificate_lookup_is_keyed_on_verified_certificate_cn() {
    expect_eq "$(section_body "${CERT_VLAN}" "files cert_vlan" | conf_value key)" \
        "%{TLS-Client-Cert-Common-Name}" "cert_vlan must look up the verified certificate CN"
    expect_match "${CERT_VLAN}" 'filename = \$\{modconfdir\}/files/authorize' \
        "cert_vlan must read the same authorize file the Deployments mount"
}

test_static_authorize_uses_only_attributes_the_policy_clears() {
    local f bad
    for f in "${AUTHORIZE_FILES[@]}"; do
        expect_no_match "$f" '^DEFAULT' "authorize must not contain DEFAULT entries (they would match any CN)"
        bad=$(grep -vE '^[[:space:]]*(#|$)' "$f" | grep -E '^[[:space:]]' \
              | sed -E 's/^[[:space:]]*([A-Za-z0-9-]+).*/\1/' \
              | grep -vxE 'Tunnel-Type|Tunnel-Medium-Type|Tunnel-Private-Group-Id' | sort -u | tr '\n' ' ')
        expect_eq "${bad}" "" "authorize reply attributes must be ones check-eap-tls clears [$(basename "$f")]"
    done
}

test_static_authorize_entries_are_unique() {
    local f dupes
    for f in "${AUTHORIZE_FILES[@]}"; do
        dupes=$(grep -E '^[^[:space:]#]' "$f" | awk '{print $1}' | sort | uniq -d | tr '\n' ' ')
        expect_eq "${dupes}" "" "each CN must appear once in authorize [$(basename "$f")]"
    done
}

# --- Identity binding (classical) --------------------------------------------

test_static_classical_binds_claimed_identity_to_certificate_cn() {
    expect_eq "$(section_body "${EAP_CLASSICAL}" "tls-config tls-common" | conf_value check_cert_cn)" \
        "%{User-Name}" "classical eap must set check_cert_cn = %{User-Name}"
}

# --- TLS policy ---------------------------------------------------------------

test_static_classical_tls_policy_is_cnsa_suite_b() {
    local body
    body=$(section_body "${EAP_CLASSICAL}" "tls-config tls-common")
    expect_eq "$(echo "${body}" | conf_value tls_min_version)" "1.2" "classical tls_min_version"
    expect_eq "$(echo "${body}" | conf_value tls_max_version)" "1.2" "classical tls_max_version"
    expect_eq "$(echo "${body}" | conf_value cipher_list)" "ECDHE-ECDSA-AES256-GCM-SHA384:@SECLEVEL=4" "classical cipher_list"
    expect_eq "$(echo "${body}" | conf_value ecdh_curve)" "secp384r1" "classical ecdh_curve"
}

test_static_pqc_tls_policy_allows_only_tls13_aes256_and_hybrid_groups() {
    local body curves g
    body=$(section_body "${EAP_PQC}" "tls-config tls-common")
    expect_eq "$(echo "${body}" | conf_value tls_min_version)" "1.3" "PQ tls_min_version"
    expect_eq "$(echo "${body}" | conf_value tls_max_version)" "1.3" "PQ tls_max_version"
    expect_eq "$(echo "${body}" | conf_value cipher_suites)" "TLS_AES_256_GCM_SHA384" "PQ cipher_suites"
    # Pinned exactly, not just its @SECLEVEL suffix: other keywords in this
    # string also apply to TLS 1.3 (a leading SUITEB192 discards the rest of
    # the string and replaces ecdh_curve with classical P-384)
    expect_eq "$(echo "${body}" | conf_value cipher_list)" "ECDHE-ECDSA-AES256-GCM-SHA384:@SECLEVEL=4" "PQ cipher_list"
    curves=$(echo "${body}" | conf_value ecdh_curve)
    [ -n "${curves}" ] || fail "PQ ecdh_curve must be set"
    for g in $(echo "${curves}" | tr ':' ' '); do
        [[ "${g}" == *MLKEM* ]] || fail "PQ ecdh_curve contains non-hybrid group ${g}"
    done
}

test_static_both_servers_hold_certificates_to_a_192_bit_security_level() {
    local f
    for f in "${EAP_CLASSICAL}" "${EAP_PQC}"; do
        [[ "$(section_body "${f}" "tls-config tls-common" | conf_value cipher_list)" == *:@SECLEVEL=4 ]] \
            || fail "cipher_list must end in :@SECLEVEL=4 [$(basename "$(dirname "$(dirname "${f}")")")]"
    done
}

test_static_both_servers_accept_only_ecdsa_p384_sha384_signatures() {
    local f
    for f in "${EAP_CLASSICAL}" "${EAP_PQC}"; do
        expect_eq "$(section_body "${f}" "tls-config tls-common" | conf_value sigalgs_list)" \
            "ecdsa_secp384r1_sha384" "sigalgs_list [$(basename "$(dirname "$(dirname "${f}")")")]"
    done
}

# OPENSSL_CONF would apply one TLS policy to every TLS connection in the
# process, overriding settings left out of each FreeRADIUS TLS section (and so
# also the future RadSec listener). Each section states its own policy instead.
test_static_no_deployment_sets_a_process_wide_openssl_config() {
    local f
    for f in "${DEPLOY_CLASSICAL}" "${DEPLOY_PQC}"; do
        grep -q OPENSSL_CONF "${f}" && fail "$(basename "${f}") must not set OPENSSL_CONF"
    done
}

test_static_session_resumption_is_disabled_on_both_servers() {
    local f
    for f in "${EAP_CLASSICAL}" "${EAP_PQC}"; do
        expect_eq "$(section_body "$f" "        cache" | conf_value enable)" "no" \
            "TLS session cache must be disabled ($(basename "$(dirname "$(dirname "$f")")"))"
    done
}

# --- RADIUS transport ---------------------------------------------------------

test_static_network_clients_require_message_authenticator() {
    local f
    for f in "${CLIENTS_FILES[@]}"; do
        awk '/^client / {name = $2; ma = ""} /require_message_authenticator/ {ma = $3}
             /^}/ && name != "" { if (name != "localhost" && ma != "yes") print name; name = "" }' "$f" \
        | while read -r c; do echo "      ✗ client ${c} must set require_message_authenticator = yes [$(basename "$f")]"; done \
        | grep . && fail "clients without require_message_authenticator"
    done
}

test_static_network_client_secrets_come_from_environment() {
    local f
    for f in "${CLIENTS_FILES[@]}"; do
        awk '/^client / {name = $2} /^[[:space:]]*secret[[:space:]]*=/ {s = $0}
             /^}/ && name != "" { if (name != "localhost" && s !~ /\$ENV\{/) print name; name = "" }' "$f" \
        | while read -r c; do echo "      ✗ client ${c} must read its secret from \$ENV{...} [$(basename "$f")]"; done \
        | grep . && fail "clients with literal secrets"
    done
}

test_static_no_client_uses_the_stock_default_secret() {
    local f
    for f in "${CLIENTS_FILES[@]}"; do
        expect_no_match "$f" "secret[[:space:]]*=[[:space:]]*['\"]?testing123" \
            "no client may use FreeRADIUS's default secret testing123 (stock proxy.conf also uses it)"
    done
}

# --- RadSec -------------------------------------------------------------------

test_static_radsec_listener_allows_only_tls13_cnsa_from_authenticators() {
    local listen tls
    listen=$(section_body "${RADSEC_SITE}" "listen")
    tls=$(section_body "${RADSEC_SITE}" "    tls")
    expect_eq "$(echo "${listen}" | conf_value port)" "2083" "RadSec port"
    expect_eq "$(echo "${listen}" | conf_value proto)" "tcp" "RadSec transport"
    expect_eq "$(echo "${listen}" | conf_value clients)" "radsec" "only the radsec client list"
    expect_eq "$(echo "${tls}" | conf_value tls_min_version)" "1.3" "RadSec tls_min_version"
    expect_eq "$(echo "${tls}" | conf_value tls_max_version)" "1.3" "RadSec tls_max_version"
    expect_eq "$(echo "${tls}" | conf_value cipher_suites)" "TLS_AES_256_GCM_SHA384" "RadSec cipher_suites"
    expect_eq "$(echo "${tls}" | conf_value cipher_list)" "ECDHE-ECDSA-AES256-GCM-SHA384:@SECLEVEL=4" "RadSec cipher_list"
    expect_eq "$(echo "${tls}" | conf_value ecdh_curve)" "secp384r1" "RadSec ecdh_curve"
    expect_eq "$(echo "${tls}" | conf_value sigalgs_list)" "ecdsa_secp384r1_sha384" "RadSec sigalgs_list"
    expect_eq "$(echo "${tls}" | conf_value require_client_cert)" "yes" "RadSec require_client_cert"
    expect_eq "$(echo "${tls}" | conf_value check_cert_issuer)" '$ENV{RADSEC_AUTHENTICATOR_ISSUER}' "RadSec check_cert_issuer"
    expect_eq "$(echo "${tls}" | conf_value ca_file)" "/etc/raddb/certs/authenticators-ca.pem" "RadSec trusts only the authenticator CA"
    echo "${tls}" | grep -Eq '^[[:space:]]*ca_path[[:space:]]*=' && fail "RadSec must not set ca_path (it would trust every CA in the directory)"
    expect_eq "$(section_body "${RADSEC_SITE}" "        cache" | conf_value enable)" "no" "RadSec session cache must be disabled"
}

test_static_radsec_is_deployed_with_its_own_trust_anchor() {
    local f
    for f in "${DEPLOY_CLASSICAL}" "${DEPLOY_PQC}"; do
        expect_match "$f" 'mountPath: /etc/raddb/sites-enabled/radsec$' "RadSec site mounted"
        expect_match "$f" 'mountPath: /etc/raddb/certs/authenticators-ca.pem$' "authenticator CA mounted"
        expect_match "$f" 'subPath: authenticators-ca.pem$' "authenticator CA mounted from its own Secret key"
        expect_match "$f" 'name: freeradius-radsec$' "issuer pin loaded from the freeradius-radsec ConfigMap"
    done
    expect_match "${KUSTOMIZE_BASE}" '^      - radsec=./config/radsec$' "RadSec site in the base ConfigMap"
    expect_match "${KUSTOMIZE_BASE}" 'authenticators-ca.pem=' "authenticator CA placeholder in the base Secret"
    expect_match "${KUSTOMIZE_BASE}" 'RADSEC_AUTHENTICATOR_ISSUER=' "issuer placeholder in the base"
    # Overlays replace the certs Secret, so each must supply the authenticator
    # CA itself, from a file other than the user-device CA
    for f in "${OVERLAY_FILES[@]}"; do
        local ca auth
        ca=$(sed -nE 's/^ *- ca\.pem=(.*)$/\1/p' "$f")
        auth=$(sed -nE 's/^ *- authenticators-ca\.pem=(.*)$/\1/p' "$f")
        [ -n "${auth}" ] || fail "overlay must map authenticators-ca.pem [$(basename "$f")]"
        [ "${auth}" != "${ca}" ] || fail "authenticators-ca.pem must not be the user-device CA [$(basename "$f")]"
        expect_match "$f" '^ *- RADSEC_AUTHENTICATOR_ISSUER=/' "overlay must set the issuer pin"
    done
}

test_static_radsec_clients_use_tls_and_the_standard_secret() {
    local f body
    for f in "${CLIENTS_FILES[@]}"; do
        body=$(section_body "$f" "clients radsec")
        [ -n "${body}" ] || { fail "a 'clients radsec' list must exist [$(basename "$f")]"; continue; }
        expect_eq "$(echo "${body}" | grep -cE '^[[:space:]]*client ')" "$(echo "${body}" | grep -cE '^[[:space:]]*proto[[:space:]]*=[[:space:]]*tls')" \
            "every radsec client must set proto = tls [$(basename "$f")]"
        echo "${body}" | grep -E '^[[:space:]]*secret[[:space:]]*=' | grep -vqE '=[[:space:]]*radsec$' \
            && fail "radsec clients use the standard secret 'radsec' [$(basename "$f")]"
    done
}

# --- Logging ------------------------------------------------------------------

test_static_servers_run_without_debug_output() {
    local f args
    for f in "${DEPLOY_CLASSICAL}" "${DEPLOY_PQC}"; do
        args=$(sed -nE 's/^ +args: *\[(.*)\].*$/\1/p' "$f")
        [ -n "${args}" ] || fail "$(basename "$f") must set radiusd args explicitly"
        echo "${args}" | grep -Eq '"-[A-Za-z]*[Xx]' && fail "$(basename "$f") args must not enable debug output (${args})"
    done
    expect_no_match "${DOCKERFILE}" '^CMD .*"-[A-Za-z]*[Xx]' "image default command must not enable debug output"
}

test_static_admission_log_records_only_allowlisted_fields() {
    expect_no_match "${CERT_LOG}" '^[^#]*%\{[^}]*(MPPE|Password|User-Name|EAP-Message|State)' \
        "cert_log formats must not include keys, passwords, claimed identities or EAP data"
    expect_eq "$(grep -cE '^[[:space:]]*filename = /dev/stdout$' "${CERT_LOG}")" "$(grep -cE '^linelog ' "${CERT_LOG}")" \
        "every cert_log instance must write to stdout"
}

# Which AP relayed each decision: its name (nas=, as the AP reports it) and the
# address the request arrived from (src=, its own RadSec connection)
test_static_admission_log_records_the_ap_name_and_address() {
    local decisions
    decisions=$(grep -E 'EAP-TLS (admitted|rejected)' "${CERT_LOG}")
    expect_eq "$(echo "${decisions}" | grep -cF 'nas=\"%{outer.request:NAS-Identifier}\"')" "2" "both decision lines log the AP name"
    expect_eq "$(echo "${decisions}" | grep -cF 'src=%{outer.request:Packet-Src-IP-Address}')" "2" "both decision lines log the source address"
}

# --- Kubernetes ---------------------------------------------------------------

test_static_containers_run_unprivileged() {
    local f
    for f in "${DEPLOY_CLASSICAL}" "${DEPLOY_PQC}"; do
        expect_match "$f" 'runAsNonRoot: true' "runAsNonRoot"
        expect_match "$f" 'allowPrivilegeEscalation: false' "allowPrivilegeEscalation: false"
        expect_match "$f" '^ +- ALL$' "capabilities drop ALL"
        expect_match "$f" 'type: RuntimeDefault' "seccomp RuntimeDefault"
        expect_no_match "$f" 'hostNetwork: true|privileged: true' "no host network or privileged mode"
    done
}

test_static_images_are_pinned_by_digest() {
    local f
    for f in "${DEPLOY_CLASSICAL}" "${DEPLOY_PQC}"; do
        expect_match "$f" 'image: [^ ]+@sha256:[0-9a-f]{64}( +#.*)?$' "image must be pinned by digest"
    done
    expect_eq "$(sed -nE 's/^ +image: +([^ #]+).*$/\1/p' "${DEPLOY_CLASSICAL}")" \
              "$(sed -nE 's/^ +image: +([^ #]+).*$/\1/p' "${DEPLOY_PQC}")" "both servers must run the same image"
}

test_static_secrets_and_keys_are_mounted_read_only_and_not_world_readable() {
    local f
    for f in "${DEPLOY_CLASSICAL}" "${DEPLOY_PQC}"; do
        expect_no_match "$f" 'readOnly: false' "no writable config or secret mounts"
        expect_no_match "$f" 'defaultMode: 0?[0-7][0-7][1-7]$' "mounted files must not be world-accessible"
    done
}

# The Deployments mount k8s/config/radiusd.conf over the image's copy. The
# default site runs 'suffix', so with proxying on, a realm in the claimed
# identity (chosen by the supplicant before any certificate is checked) could
# send the request to another server instead of through the admission policy.
test_static_server_config_turns_proxying_off() {
    local conf
    conf=$(sed 's/#.*//' "${RADIUSD_CONF}")
    expect_eq "$(echo "${conf}" | conf_value proxy_requests)" "no" "radiusd.conf must turn proxying off"
    if echo "${conf}" | grep -Eq '^[[:space:]]*\$INCLUDE[[:space:]]+proxy\.conf'; then
        fail "radiusd.conf must not include proxy.conf"
    fi
}

# A config change reaches the cluster with 'kubectl apply -k' alone: kustomize
# names each generated ConfigMap after a hash of its contents, so the pod
# template changes and a new pod starts. radiusd exits at once on broken
# configuration, so a new pod that must stay up for minReadySeconds before the
# old one is removed (maxUnavailable: 0) never replaces a working server.
test_static_config_changes_roll_out_without_replacing_a_working_server() {
    local f n
    expect_match "${KUSTOMIZE_BASE}" '^ +- radiusd\.conf=\./config/radiusd\.conf$' "freeradius-config must include radiusd.conf"
    for f in "${KUSTOMIZE_BASE}" "${KUSTOMIZE_PQC}" "${OVERLAY_FILES[@]}"; do
        expect_no_match "$f" 'disableNameSuffixHash: *true' "generated ConfigMap names must keep their content hash"
    done
    for f in "${DEPLOY_CLASSICAL}" "${DEPLOY_PQC}"; do
        n=$(sed -nE 's/^  minReadySeconds: *([0-9]+)$/\1/p' "$f")
        [ "${n:-0}" -ge 10 ] || fail "$(basename "$f") must set minReadySeconds >= 10 (got '${n}')"
        expect_match "$f" '^      maxUnavailable: 0$' "rollouts must not remove the old pod first (maxUnavailable: 0)"
        expect_no_match "$f" 'type: Recreate' "rollouts must not use the Recreate strategy"
    done
}

test_static_overlays_merge_rather_than_replace_the_shared_config() {
    local f
    for f in "${OVERLAY_FILES[@]}"; do
        awk '/- name: / {inside = ($0 ~ /- name: freeradius-config$/)} inside && /behavior:/ {print}' "$f" \
            | grep -q 'behavior: merge' \
            || fail "freeradius-config must use behavior: merge [$(basename "$f")]"
    done
}

# ==============================================================================
# Image tests: stock configuration shipped in the pinned image
# ==============================================================================

# The image's own default radiusd.conf (a copy of k8s/config/radiusd.conf, used
# when the Deployments' mount is absent) turns proxying off and does not read
# proxy.conf at all.
test_image_does_not_proxy_realm_suffixed_identities() {
    local conf
    conf=$(${CLI} run --rm --entrypoint sh "${RADIUS_IMAGE}" -c "sed 's/#.*//' /etc/raddb/radiusd.conf" 2>/dev/null)
    [ -n "${conf}" ] || fail "could not read radiusd.conf from the image"
    expect_eq "$(echo "${conf}" | conf_value proxy_requests)" "no" "radiusd.conf must turn proxying off"
    if echo "${conf}" | grep -Eq '^[[:space:]]*\$INCLUDE[[:space:]]+proxy\.conf'; then
        fail "radiusd.conf must not include proxy.conf"
    fi
}

test_image_enables_no_unexpected_virtual_servers() {
    local sites
    sites=$(${CLI} run --rm --entrypoint ls "${RADIUS_IMAGE}" /etc/raddb/sites-enabled 2>/dev/null | sort | tr '\n' ' ')
    expect_eq "${sites}" "default inner-tunnel " "stock sites-enabled (check-eap-tls is added by mount)"
}

# ==============================================================================
# Functional lab
# ==============================================================================
lab_setup() {
    if command -v podman >/dev/null 2>&1; then CLI=podman
    elif command -v docker >/dev/null 2>&1; then CLI=docker
    else echo "❌ podman or docker is required for the functional tests (use --static)" >&2; exit 1; fi

    RADIUS_IMAGE="${RADIUS_IMAGE:-$(sed -nE 's/^ +image: +([^ #]+).*$/\1/p' "${DEPLOY_CLASSICAL}" | head -n1)}"
    EAPOL_IMAGE="${EAPOL_IMAGE:-eapol-test:pqc}"
    local img
    for img in "${RADIUS_IMAGE}" "${EAPOL_IMAGE}"; do
        ${CLI} image inspect "${img}" >/dev/null 2>&1 || {
            echo "❌ Image not available locally: ${img}" >&2
            echo "   Pull or build it (see this script's header), or set RADIUS_IMAGE / EAPOL_IMAGE." >&2
            exit 1; }
    done
    local usage; usage=$(${CLI} run --rm "${EAPOL_IMAGE}" -h 2>&1)
    echo "${usage}" | grep -q -- '-J<client cert>' || {
        echo "❌ ${EAPOL_IMAGE} has no RadSec support (eapol_test -X TLS)." >&2
        echo "   Rebuild it from test/Dockerfile, which sets CONFIG_RADIUS_TLS=y (see this script's header)." >&2
        exit 1; }
    read -r -a RADIUSD_ARGS <<< "$(sed -nE 's/^ +args: *\[(.*)\].*$/\1/p' "${DEPLOY_CLASSICAL}" | tr -d '",')"

    WORK="$(mktemp -d "${TMPDIR:-/tmp}/guarantees.XXXXXX")"
    NET="guarantees-$$"; SRV="guarantees-radius-$$"; SRV_IP=10.1.0.10
    # Fixed address for eapol_test when it stands in for an access point over
    # RadSec, so the server's log can be checked for it (src=)
    AP_IP=10.1.0.30
    # A second lab network outside every client list (the radsec list and the
    # UDP ones), which the server is also attached to
    OUT_NET="guarantees-outside-$$"; OUT_SRV_IP=10.99.0.10; OUT_CLIENT_IP=10.99.0.30
    # Subject of the lab authenticator CA, pinned by the RadSec listener
    RADSEC_ISSUER="/CN=Lab Root CA - Network Authenticators"
    AUTH_SECRET="lab$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 40)"
    TEST_SECRET="lab$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 40)"
    trap lab_teardown EXIT
    mkdir -p "${WORK}/pki" "${WORK}/conf"

    # Throwaway PKI (OpenSSL 3.5 in the eapol_test image). Leaf EKUs match the
    # step CLI 'leaf' profile used by certificate-authority/generate-certs.sh.
    cat > "${WORK}/pki/make.sh" <<'EOF'
set -eu
cd /pki
CURVE=P-384 DIGEST=sha384
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$CURVE -out "$1" 2>/dev/null; }
ca() { key "$1.key"; openssl req -x509 -new -key "$1.key" -sha384 -days 3 -subj "/CN=$2" \
       -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -out "$1.crt"; }
leaf() { # file cn issuer [x509 validity args]
    f=$1 cn=$2 iss=$3; shift 3
    key "$f.key"; openssl req -new -key "$f.key" -subj "/CN=$cn" -out "$f.csr"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n' > "$f.ext"
    [ $# -gt 0 ] || set -- -days 3
    openssl x509 -req -in "$f.csr" -CA "$iss.crt" -CAkey "$iss.key" -CAcreateserial -$DIGEST -extfile "$f.ext" -out "$f.crt" "$@" 2>/dev/null
}
ca user_ca   "Lab Root CA - User Endpoints"
ca server_ca "Lab Root CA - RADIUS Server"
ca other_ca  "Lab Root CA - Unrelated"
leaf server  radius.lab       server_ca
cat server.key server.crt > server.pem
leaf dev01   client-device-01 user_ca
leaf dev02   client-device-02 user_ca
leaf dev99   client-device-99 user_ca
leaf expired client-device-01 user_ca -not_before 20200101000000Z -not_after 20200102000000Z
leaf other   client-device-01 other_ca
# Same device, CA and authorize entry as dev01, but a P-256 key
CURVE=P-256; leaf dev01p256 client-device-01 user_ca; CURVE=P-384
# Same device, CA and authorize entry as dev01, but signed by the CA with SHA-256
DIGEST=sha256; leaf dev01sha256 client-device-01 user_ca; DIGEST=sha384
# Access point RadSec client certificates: one shared by every AP, as UniFi
# does, plus a P-256 copy and a copy the CA signed with SHA-256
ca ap_ca "Lab Root CA - Network Authenticators"
leaf ap lab-aps ap_ca
cat ap.key ap.crt > ap.pem
CURVE=P-256; leaf ap_p256 lab-aps ap_ca; CURVE=P-384
DIGEST=sha256; leaf ap_sha256 lab-aps ap_ca; DIGEST=sha384
chmod 644 ./*
EOF
    ${CLI} run --rm --entrypoint sh -v "${WORK}/pki:/pki" "${EAPOL_IMAGE}" /pki/make.sh >/dev/null || {
        echo "❌ Lab PKI generation failed" >&2; exit 1; }

    # clients.conf.example as shipped; only the localhost secret is given a
    # value so the file loads. Lab clients sit in its authenticator subnet.
    sed -E "/client localhost/,/}/ s/secret = .*/secret = '$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 24)'/" \
        "${REPO}/k8s/config/clients.conf.example" > "${WORK}/conf/clients.conf"
    { cat "${REPO}/k8s/config/authorize.example"
      printf '\nclient-device-02\n    Tunnel-Type = VLAN,\n    Tunnel-Medium-Type = IEEE-802,\n    Tunnel-Private-Group-Id = "30"\n'
      # The APs' shared certificate CN, so a policy that keyed on it would show
      printf '\nlab-aps\n    Tunnel-Type = VLAN,\n    Tunnel-Medium-Type = IEEE-802,\n    Tunnel-Private-Group-Id = "99"\n'; } \
        > "${WORK}/conf/authorize"
    printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nGroups = %s\n' "X25519:P-256" > "${WORK}/conf/cl-classical-groups.cnf"
    printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nSignatureAlgorithms = %s\n' "ECDSA+SHA256" > "${WORK}/conf/cl-sigalgs-sha256.cnf"
    printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nGroups = %s\n' "X25519MLKEM768" > "${WORK}/conf/cl-x25519mlkem768.cnf"
    printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nGroups = %s\n' "SecP384r1MLKEM1024" > "${WORK}/conf/cl-secp384r1mlkem1024.cnf"
    printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nCiphersuites = %s\n' "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256" > "${WORK}/conf/cl-aes128.cnf"
    # One client configuration per TLS 1.3 cipher suite, and one offering all.
    # Security level 0, or the client's OpenSSL silently drops
    # TLS_AES_128_CCM_8_SHA256; the server's policy alone must decide.
    local suite offer
    for suite in "${TLS13_SUITES[@]}" all; do
        offer=${suite}
        [ "${suite}" = all ] && offer=$(IFS=:; echo "${TLS13_SUITES[*]}")
        printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nCipherString = DEFAULT:@SECLEVEL=0\nCiphersuites = %s\n' "${offer}" \
            > "${WORK}/conf/cl-suite-${suite}.cnf"
    done
    # One client configuration per classical key exchange group
    local group
    for group in "${CLASSICAL_GROUPS[@]}"; do
        printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nGroups = %s\n' "${group}" \
            > "${WORK}/conf/cl-group-${group}.cnf"
    done
    chmod 644 "${WORK}/conf/"*

    # What a UniFi AP (U6-Mesh, firmware 6.8.2) offers when it opens a RadSec
    # connection, as seen in the hardening plan's Phase 0. Its RADIUS client is
    # hostapd (wpad) on OpenSSL 1.1.1, and hostapd sets no TLS policy beyond
    # "no TLS 1.0 or 1.1", so the offer is OpenSSL 1.1.1's defaults: TLS 1.3
    # and 1.2, AES-256-GCM and AES-128-GCM, these groups in this order, and a
    # key share for x25519 only. eapol_test (hostapd's RADIUS client, built on
    # OpenSSL 3.5) is shaped to send the same. One OpenSSL configuration covers
    # both of eapol_test's roles, AP and device, so on the PQC server the
    # device's hybrid group is appended to the list; the RadSec listener
    # ignores it. Not reproduced: OpenSSL 3.5 also lists ML-DSA and brainpool
    # signature algorithms, which 1.1.1 does not.
    local ap_groups="X25519:P-256:X448:P-521:P-384"
    printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nGroups = %s\nCiphersuites = TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256\n' \
        "${ap_groups}" > "${WORK}/conf/cl-ap-classical.cnf"
    printf 'openssl_conf = i\n[i]\nssl_conf = s\n[s]\nsystem_default = d\n[d]\nGroups = %s\nCiphersuites = TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256\n' \
        "${ap_groups}:X25519MLKEM768" > "${WORK}/conf/cl-ap-pqc.cnf"
    chmod 644 "${WORK}/conf/"cl-ap-*.cnf

    ${CLI} network create --subnet 10.1.0.0/24 "${NET}" >/dev/null
    ${CLI} network create --subnet 10.99.0.0/24 "${OUT_NET}" >/dev/null
}

lab_teardown() {
    ${CLI} rm -f "${SRV}" >/dev/null 2>&1 || true
    ${CLI} network rm "${NET}" "${OUT_NET}" >/dev/null 2>&1 || true
    if [ "${KEEP}" = true ]; then echo "Work directory kept: ${WORK}"; else rm -rf "${WORK}"; fi
}

start_server() { # classical|pqc
    local eap=${EAP_CLASSICAL}
    [ "$1" = pqc ] && eap=${EAP_PQC}
    ${CLI} rm -f "${SRV}" >/dev/null 2>&1
    ${CLI} run -d --name "${SRV}" --network "${NET}" --ip "${SRV_IP}" \
        -e RADIUS_SECRET_AUTHENTICATORS="${AUTH_SECRET}" -e RADIUS_SECRET_TEST="${TEST_SECRET}" \
        -e RADSEC_AUTHENTICATOR_ISSUER="${RADSEC_ISSUER}" \
        -v "${WORK}/pki/ap_ca.crt:/etc/raddb/certs/authenticators-ca.pem:ro" \
        -v "${RADSEC_SITE}:/etc/raddb/sites-enabled/radsec:ro" \
        -v "${WORK}/pki/user_ca.crt:/etc/raddb/certs/ca.pem:ro" \
        -v "${WORK}/pki/server.pem:/etc/raddb/certs/server.pem:ro" \
        -v "${RADIUSD_CONF}:/etc/raddb/radiusd.conf:ro" \
        -v "${WORK}/conf/clients.conf:/etc/raddb/clients.conf:ro" \
        -v "${WORK}/conf/authorize:/etc/raddb/mods-config/files/authorize:ro" \
        -v "${eap}:/etc/raddb/mods-enabled/eap:ro" \
        -v "${CHECK_EAP_TLS}:/etc/raddb/sites-enabled/check-eap-tls:ro" \
        -v "${CERT_VLAN}:/etc/raddb/mods-enabled/cert_vlan:ro" \
        -v "${CERT_LOG}:/etc/raddb/mods-enabled/cert_log:ro" \
        "${RADIUS_IMAGE}" "${RADIUSD_ARGS[@]}" >/dev/null
    ${CLI} network connect --ip "${OUT_SRV_IP}" "${OUT_NET}" "${SRV}" >/dev/null
    local i
    for i in $(seq 60); do
        server_log | grep -c "Ready to process requests" >/dev/null && { EAP_SUCCESSES=0; return 0; }
        ${CLI} ps -q -f name="${SRV}" | grep -q . || break
        sleep 0.25
    done
    echo "❌ $1 server did not start:" >&2; ${CLI} logs "${SRV}" >&2; exit 1
}

# Captured before filtering: with pipefail, grep -q closing the pipe early
# would make the pipeline fail
server_log() { local log; log=$(${CLI} logs "${SRV}" 2>&1); printf '%s\n' "${log}"; }

# ------------------------------------------------------------------------------
# eap <cert|none> <identity> [options]: one EAP authentication
#   --tls tls12|tls13|tls12or13|weak|peap|ttls  (default: the server's own TLS version)
#   --groups <client config name>     client OpenSSL configuration (cl-<name>.cnf)
#   --secret <secret>                 shared secret (default: the lab secret)
#   --reauth                          authenticate twice in one run
#   --called <AP MAC>:<SSID>          send this Called-Station-Id, as an AP does
#   --via-radsec                      as an access point would: RadSec to port 2083
#                                     with the lab AP certificate and an AP's TLS offer
# Sets EAP_RESULT (SUCCESS|FAILURE), EAP_VLANS (VLANs in the final
# Access-Accept, comma-separated), EAP_USER (its User-Name), EAP_OUT (file)
# ------------------------------------------------------------------------------
EAP_N=0
eap() {
    local cert=$1 identity=$2 tls=default groups="" secret="${AUTH_SECRET}" extra=() radsec=false
    shift 2
    while [ $# -gt 0 ]; do
        case "$1" in
            --tls) tls=$2; shift 2 ;;
            --groups) groups=$2; shift 2 ;;
            --secret) secret=$2; shift 2 ;;
            --reauth) extra+=(-r1); shift ;;
            --called) extra+=(-N"30:s:$2"); shift 2 ;;   # Called-Station-Id
            --via-radsec) radsec=true; shift ;;
        esac
    done
    [ "${tls}" = default ] && { [ "${MODE}" = pqc ] && tls=tls13 || tls=tls12; }
    [ "${tls}" = weak ] && [ "${MODE}" = pqc ] && { tls=tls13; groups=aes128; }

    EAP_N=$((EAP_N + 1))
    local conf="${WORK}/conf/${MODE}-${EAP_N}.conf" method=TLS phase1="" ciphers=""
    EAP_OUT="${WORK}/${MODE}-${EAP_N}-${FUNCNAME[1]}.out"
    case "${tls}" in
        tls12) phase1="tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1 tls_disable_tlsv1_3=1"; ciphers="ECDHE-ECDSA-AES256-GCM-SHA384" ;;
        weak)  phase1="tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1 tls_disable_tlsv1_3=1"; ciphers="ECDHE-ECDSA-AES128-GCM-SHA256" ;;
        tls13) phase1="tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1 tls_disable_tlsv1_2=1 tls_disable_tlsv1_3=0" ;;
        tls12or13) phase1="tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1 tls_disable_tlsv1_2=0 tls_disable_tlsv1_3=0" ;;
        peap)  method=PEAP ;;
        ttls)  method=TTLS ;;
    esac
    {
        echo "network={"
        echo "    key_mgmt=WPA-EAP"
        echo "    eap=${method}"
        echo "    identity=\"${identity}\""
        echo "    ca_cert=\"/pki/server_ca.crt\""
        if [ "${method}" = TLS ] && [ "${cert}" != none ]; then
            echo "    client_cert=\"/pki/${cert}.crt\""
            echo "    private_key=\"/pki/${cert}.key\""
        fi
        [ -n "${phase1}" ] && echo "    phase1=\"${phase1}\""
        [ -n "${ciphers}" ] && echo "    openssl_ciphers=\"${ciphers}\""
        [ "${method}" = PEAP ] && { echo '    password="lab-password"'; echo '    phase2="auth=MSCHAPV2"'; }
        [ "${method}" = TTLS ] && { echo '    password="lab-password"'; echo '    phase2="auth=PAP"'; }
        echo "}"
    } > "${conf}"
    chmod 644 "${conf}"

    local env=() port=1812 net=()
    [ -n "${groups}" ] && env=(-e "OPENSSL_CONF=/conf/cl-${groups}.cnf")
    if [ "${radsec}" = true ]; then
        port=2083; secret=radsec; net=(--ip "${AP_IP}")
        env=(-e "OPENSSL_CONF=/conf/cl-ap-${MODE}.cnf")
        extra+=(-X TLS -j /pki/server_ca.crt -J /pki/ap.crt -k /pki/ap.key)
    fi
    ${CLI} run --rm --network "${NET}" ${net[@]+"${net[@]}"} ${env[@]+"${env[@]}"} \
        -v "${WORK}/pki:/pki:ro" -v "${WORK}/conf:/conf:ro" "${EAPOL_IMAGE}" \
        -c "/conf/$(basename "${conf}")" -a "${SRV_IP}" -p "${port}" -s "${secret}" \
        -M 02:00:00:00:00:01 -t 15 ${extra[@]+"${extra[@]}"} > "${EAP_OUT}" 2>&1
    EAP_RESULT=$(grep -E '^(SUCCESS|FAILURE)$' "${EAP_OUT}" | tail -n1)
    EAP_RESULT=${EAP_RESULT:-FAILURE}
    local successes
    successes=$(grep -c 'CTRL-EVENT-EAP-SUCCESS' "${EAP_OUT}")
    EAP_SUCCESSES=$(( EAP_SUCCESSES + successes ))
    # Attributes of the last Access-Accept only (Access-Challenges are ignored)
    local accept
    accept=$(awk '/^RADIUS message: code=/ {keep = ($0 ~ /code=2 /); if (keep) buf = ""}
                  keep {buf = buf $0 "\n"} END {printf "%s", buf}' "${EAP_OUT}")
    EAP_VLANS=$(echo "${accept}" | awk '/Attribute 81 / {getline; sub(/.*Value: /, ""); print}' \
        | while read -r hex; do printf '%s' "${hex}" | sed -E 's/^(0[0-9a-f]|1[0-9a-f])(3)/\2/' | xxd -r -p; echo; done \
        | paste -sd, -)
    EAP_USER=$(echo "${accept}" | awk '/Attribute 1 \(User-Name\)/ {getline; sub(/.*Value: /, ""); gsub(/\x27/, ""); print}' | head -n1)
}

expect_accept() { # vlan [cn]
    expect_eq "${EAP_RESULT}" "SUCCESS" "authentication result"
    expect_eq "${EAP_VLANS}" "$1" "VLAN attributes in the Access-Accept (exactly one, from the certificate's entry)"
    [ $# -lt 2 ] || expect_eq "${EAP_USER}" "$2" "Access-Accept User-Name must be the certificate CN"
}
expect_reject() {
    expect_eq "${EAP_RESULT}" "FAILURE" "authentication result"
    expect_eq "${EAP_VLANS}" "" "no Access-Accept"
}

# ------------------------------------------------------------------------------
# What the last eap run offered and negotiated, read from the raw handshake
# messages in the client's log and from the server's admission log
# ------------------------------------------------------------------------------
# Hex bytes of the first handshake message whose log line matches $1
hello_bytes() {
    awk -v pat="$1" '$0 ~ pat {getline; sub(/.*hexdump\(len=[0-9]+\): /, ""); print; exit}' "${EAP_OUT}"
}
suite_name() {
    case "$1" in
        1301) echo TLS_AES_128_GCM_SHA256 ;;       1302) echo TLS_AES_256_GCM_SHA384 ;;
        1303) echo TLS_CHACHA20_POLY1305_SHA256 ;; 1304) echo TLS_AES_128_CCM_SHA256 ;;
        1305) echo TLS_AES_128_CCM_8_SHA256 ;;     *) echo "0x$1" ;;
    esac
}
# TLS 1.3 cipher suites in the client's ClientHello, comma-separated
offered_tls13_suites() {
    local b i n c out=()
    read -r -a b <<< "$(hello_bytes 'TX ver=.*\(handshake/client hello\)')"
    [ ${#b[@]} -gt 40 ] || return 0
    i=$((39 + 16#${b[38]}))    # skip type, length, version, random and session ID
    n=$(( (16#${b[i]} * 256 + 16#${b[i+1]}) / 2 )); i=$((i + 2))
    for (( ; n > 0; n--, i += 2 )); do
        c="${b[i]}${b[i+1]}"
        [[ "${c}" == 13* ]] && out+=("$(suite_name "${c}")")
    done
    (IFS=,; echo "${out[*]}")
}
group_name() {
    case "$1" in
        001d) echo X25519 ;; 001e) echo X448 ;;
        0017) echo P-256 ;;  0018) echo P-384 ;; 0019) echo P-521 ;;
        11ec) echo X25519MLKEM768 ;; 11ed) echo SecP384r1MLKEM1024 ;;
        *) echo "0x$1" ;;
    esac
}
# Key exchange groups in the client's ClientHello (supported_groups
# extension), comma-separated
offered_groups() {
    local b i n end type len out=()
    read -r -a b <<< "$(hello_bytes 'TX ver=.*\(handshake/client hello\)')"
    [ ${#b[@]} -gt 40 ] || return 0
    i=$((39 + 16#${b[38]}))                              # cipher suites
    i=$((i + 2 + 16#${b[i]} * 256 + 16#${b[i+1]}))       # compression methods
    i=$((i + 1 + 16#${b[i]}))                            # extensions
    end=$((i + 2 + 16#${b[i]} * 256 + 16#${b[i+1]})); i=$((i + 2))
    while [ "${i}" -lt "${end}" ]; do
        type="${b[i]}${b[i+1]}"; len=$((16#${b[i+2]} * 256 + 16#${b[i+3]})); i=$((i + 4))
        if [ "${type}" = 000a ]; then
            n=$(( (16#${b[i]} * 256 + 16#${b[i+1]}) / 2 ))
            for (( i += 2; n > 0; n--, i += 2 )); do out+=("$(group_name "${b[i]}${b[i+1]}")"); done
            break
        fi
        i=$((i + len))
    done
    (IFS=,; echo "${out[*]}")
}
# Data of one extension (hex type, e.g. 002b) in the client's first
# ClientHello, as space-separated hex bytes
hello_ext() {
    local b i end type len
    read -r -a b <<< "$(hello_bytes 'TX ver=.*\(handshake/client hello\)')"
    [ ${#b[@]} -gt 40 ] || return 0
    i=$((39 + 16#${b[38]}))
    i=$((i + 2 + 16#${b[i]} * 256 + 16#${b[i+1]}))
    i=$((i + 1 + 16#${b[i]}))
    end=$((i + 2 + 16#${b[i]} * 256 + 16#${b[i+1]})); i=$((i + 2))
    while [ "${i}" -lt "${end}" ]; do
        type="${b[i]}${b[i+1]}"; len=$((16#${b[i+2]} * 256 + 16#${b[i+3]})); i=$((i + 4))
        [ "${type}" = "$1" ] && { echo "${b[*]:i:len}"; return 0; }
        i=$((i + len))
    done
}
# TLS versions in the client's first ClientHello (supported_versions)
offered_versions() {
    local d out=() k v
    read -r -a d <<< "$(hello_ext 002b)"
    for (( k = 1; k < 1 + 16#${d[0]:-0}; k += 2 )); do
        v="${d[k]}${d[k+1]}"
        case "${v}" in 0304) out+=("TLS 1.3") ;; 0303) out+=("TLS 1.2") ;; *) out+=("0x${v}") ;; esac
    done
    (IFS=,; echo "${out[*]}")
}
# Groups the client sent key shares for in its first ClientHello
offered_key_shares() {
    local d out=() k=2
    read -r -a d <<< "$(hello_ext 0033)"
    while [ "${k}" -lt "${#d[@]}" ]; do
        out+=("$(group_name "${d[k]}${d[k+1]}")")
        k=$((k + 4 + 16#${d[k+2]} * 256 + 16#${d[k+3]}))
    done
    (IFS=,; echo "${out[*]}")
}
# Cipher suite chosen in the ServerHello the client received
server_hello_suite() {
    local b i
    read -r -a b <<< "$(hello_bytes 'RX ver=.*\(handshake/server hello\)')"
    [ ${#b[@]} -gt 40 ] || return 0
    i=$((39 + 16#${b[38]}))
    suite_name "${b[i]}${b[i+1]}"
}
expect_negotiated() { # version suite: as seen by the client and by the server
    local line
    line=$(server_log | grep 'EAP-TLS admitted' | tail -n1)
    expect_eq "$(grep 'SSL: Using TLS version' "${EAP_OUT}" | tail -n1 | awk '{print $NF}')" "TLSv${1#TLS }" \
        "client: negotiated TLS version"
    expect_eq "$(server_hello_suite)" "$2" "client: cipher suite in the ServerHello"
    expect_eq "$(echo "${line}" | sed -nE 's/.* tls="([^"]*)".*/\1/p')" "$1" "server: TLS version in cert_log"
    expect_eq "$(echo "${line}" | sed -nE 's/.* cipher=([^ ]*).*/\1/p')" "$2" "server: cipher suite in cert_log"
}

# ------------------------------------------------------------------------------
# radsec_connect <cert|none> [openssl s_client args]: one TLS connection to the
# server's RadSec port, presenting /pki/<cert>.crt as an access point would.
# The client keeps the connection open for 2 s: in TLS 1.3 the server checks
# the client certificate only after the client's Finished, when the client
# already considers the handshake complete. FreeRADIUS then drops a refused
# connection without the client receiving its alert, so the verdict, and the
# reason for it, come from the server's log.
# Sets RADSEC_OUT (the client's output) and RADSEC_SERVER (the server's TLS
# log lines since the connection started). Set RADSEC_FROM=outside to connect
# from the lab network outside every client list.
# ------------------------------------------------------------------------------
radsec_connect() {
    local cert=$1 before i net=(--network "${NET}") host=${SRV_IP}; shift
    [ "${RADSEC_FROM:-}" = outside ] && { net=(--network "${OUT_NET}" --ip "${OUT_CLIENT_IP}"); host=${OUT_SRV_IP}; }
    local args=(-connect "${host}:2083" -CAfile /pki/server_ca.crt -verify_return_error)
    [ "${cert}" != none ] && args+=(-cert "/pki/${cert}.crt" -key "/pki/${cert}.key")
    before=$(server_log | wc -l)
    RADSEC_OUT=$(${CLI} run --rm "${net[@]}" --entrypoint sh -v "${WORK}/pki:/pki:ro" "${EAPOL_IMAGE}" \
        -c 'sleep 2 | openssl s_client "$@" 2>&1' sh "${args[@]}" "$@" 2>&1)
    for i in $(seq 20); do
        RADSEC_SERVER=$(server_log | tail -n +$((before + 1)) | grep -E 'RADIUS/TLS|OpenSSL says|Certificate issuer|unknown client')
        echo "${RADSEC_OUT}" | grep -q '^DONE$' && break
        echo "${RADSEC_SERVER}" | grep -qE 'Alert write:fatal|unknown client' && break
        sleep 0.25
    done
}
# Strict CNSA 1.0 on TLS 1.3, and the connection still open 2 s later
expect_radsec_accepted() {
    expect_eq "$(echo "${RADSEC_OUT}" | sed -nE 's/^New, (TLSv[0-9.]+), Cipher is .*/\1/p')" "TLSv1.3" "client: TLS version"
    expect_eq "$(echo "${RADSEC_OUT}" | sed -nE 's/^New, TLSv[0-9.]+, Cipher is //p')" "TLS_AES_256_GCM_SHA384" "client: cipher suite"
    expect_eq "$(echo "${RADSEC_OUT}" | sed -nE 's/^Peer Temp Key: ECDH, ([^,]*),.*/\1/p')" "secp384r1" "client: key exchange group"
    expect_eq "$(echo "${RADSEC_OUT}" | sed -nE 's/^Peer signature type: //p')" "ecdsa_secp384r1_sha384" "client: the server's signature"
    expect_eq "$(echo "${RADSEC_OUT}" | grep -c '^DONE$')" "1" "client: connection still open after 2 s, then closed by the client"
    expect_eq "$(echo "${RADSEC_SERVER}" | grep -c 'Alert write:fatal')" "0" "server: no TLS alert"
}
expect_radsec_refused() { # extended regex for the reason in the server's log
    expect_eq "$(echo "${RADSEC_OUT}" | grep -c '^DONE$')" "0" "client: connection dropped by the server"
    echo "${RADSEC_SERVER}" | grep -qE -- "$1" \
        || fail "server: expected '$1' in its log, got: $(echo "${RADSEC_SERVER}" | tr '\n' '|')"
}

# ==============================================================================
# Functional tests: both servers
# ==============================================================================

test_both_registered_certificate_gets_its_vlan_and_identity() {
    local id=client-device-01; [ "${MODE}" = pqc ] && id=anonymous
    eap dev01 "${id}"; expect_accept 10 client-device-01
}

test_both_each_certificate_gets_its_own_vlan() {
    eap dev02 client-device-02; expect_accept 30 client-device-02
}

test_both_certificate_without_authorize_entry_is_rejected() {
    eap dev99 client-device-99; expect_reject
}

test_both_certificate_from_an_untrusted_ca_is_rejected() {
    eap other client-device-01; expect_reject
}

test_both_server_certificate_is_not_accepted_as_a_client_certificate() {
    eap server radius.lab; expect_reject
}

test_both_expired_certificate_is_rejected() {
    eap expired client-device-01; expect_reject
}

test_both_authentication_without_a_client_certificate_is_rejected() {
    eap none client-device-01; expect_reject
}

test_both_password_based_eap_methods_are_rejected() {
    eap none client-device-01 --tls peap; expect_reject
    eap none client-device-01 --tls ttls; expect_reject
}

test_both_pap_is_rejected_for_a_registered_name() {
    local out
    out=$(echo 'User-Name = "client-device-01", User-Password = "lab-password"' \
        | ${CLI} run --rm -i --network "${NET}" --entrypoint radclient "${RADIUS_IMAGE}" \
            -r 1 -t 3 -x "${SRV_IP}:1812" auth "${AUTH_SECRET}" 2>&1)
    echo "${out}" | grep -q 'Received Access-Reject' || fail "PAP must be answered with Access-Reject"
}

test_both_wrong_shared_secret_gets_no_answer() {
    eap dev01 client-device-01 --secret "wrong-${AUTH_SECRET}"
    expect_eq "${EAP_RESULT}" "FAILURE" "authentication result"
    grep -q 'Received RADIUS message' "${EAP_OUT}" && fail "the server must not answer a request with the wrong secret"
    server_log | grep -c 'Shared secret is incorrect' >/dev/null || fail "the server should log the shared secret mismatch"
}

# The SSID an AP reports in Called-Station-Id ("<AP radio MAC>:<SSID>",
# RFC 3580) is logged as its own field, for admissions and rejections, while
# called= still shows the attribute exactly as the AP sent it
test_both_cert_log_records_the_ssid() {
    local id=client-device-01 called=02-00-00-00-00-AA:ENTERPRISE-WIFI kind line i
    [ "${MODE}" = pqc ] && id=anonymous
    eap dev01 "${id}" --called "${called}"; expect_accept 10
    eap dev99 client-device-99 --called "${called}"; expect_reject
    for kind in admitted rejected; do
        for i in $(seq 20); do
            line=$(server_log | grep "EAP-TLS ${kind}" | grep -F "called=\"${called}\"" | tail -n1)
            [ -n "${line}" ] && break
            sleep 0.25
        done
        expect_eq "$(echo "${line}" | sed -nE 's/.* ssid="([^"]*)".*/\1/p')" "ENTERPRISE-WIFI" "ssid= on the ${kind} line"
        expect_eq "$(echo "${line}" | sed -nE 's/.* called="([^"]*)".*/\1/p')" "${called}" "called= on the ${kind} line, unchanged"
    done
}

# Every EAP-TLS authentication that reaches the server over plain UDP RADIUS
# logs a warning naming the client; over RadSec it must not
test_both_plaintext_radius_is_logged_as_a_warning() {
    local before after line i id=client-device-01
    [ "${MODE}" = pqc ] && id=anonymous
    before=$(server_log | grep -c 'WARNING: RADIUS over plaintext UDP')
    eap dev01 "${id}"; expect_accept 10
    for i in $(seq 20); do
        line=$(server_log | grep 'WARNING: RADIUS over plaintext UDP' | tail -n1)
        [ "$(server_log | grep -c 'WARNING: RADIUS over plaintext UDP')" -gt "${before}" ] && break
        sleep 0.25
    done
    expect_eq "$(( $(server_log | grep -c 'WARNING: RADIUS over plaintext UDP') - before ))" "1" "one warning for the UDP authentication"
    expect_eq "$(echo "${line}" | sed -nE 's/.* client=([^ ]*) .*/\1/p')" "network_authenticators" "warning names the RADIUS client"
    expect_eq "$(echo "${line}" | sed -nE 's/.* port=([0-9]+)\..*/\1/p')" "1812" "warning names the UDP port"
    # Over RadSec: wait for this authentication's admission line, which is
    # logged after the point where the warning would be, so a late warning
    # cannot slip past the check
    local admitted
    before=$(server_log | grep -c 'WARNING: RADIUS over plaintext UDP')
    admitted=$(server_log | grep -c "EAP-TLS admitted: .* src=${AP_IP} ")
    eap dev01 "${id}" --via-radsec; expect_accept 10
    for i in $(seq 20); do
        [ "$(server_log | grep -c "EAP-TLS admitted: .* src=${AP_IP} ")" -gt "${admitted}" ] && break
        sleep 0.25
    done
    expect_eq "$(( $(server_log | grep -c "EAP-TLS admitted: .* src=${AP_IP} ") - admitted ))" "1" "RadSec authentication logged"
    expect_eq "$(( $(server_log | grep -c 'WARNING: RADIUS over plaintext UDP') - before ))" "0" "no warning over RadSec"
}

test_both_reauthentication_applies_the_policy_again() {
    local before after
    before=$(server_log | grep -c 'EAP-TLS admitted')
    eap dev02 client-device-02 --reauth
    after=$(server_log | grep -c 'EAP-TLS admitted')
    expect_eq "$(grep -c 'CTRL-EVENT-EAP-SUCCESS' "${EAP_OUT}")" "2" "two successful authentications"
    expect_eq "$((after - before))" "2" "the admission policy must run for each authentication"
    expect_accept 30
}

test_both_tls_negotiation_below_policy_is_rejected() {
    eap dev01 client-device-01 --tls weak; expect_reject
    eap dev01 client-device-01 --groups classical-groups; expect_reject
}

# ==============================================================================
# Functional tests: RadSec, both servers (sites-enabled/radsec)
# The access points' link: strict CNSA 1.0 on TLS 1.3 only, AP certificates only
# ==============================================================================

# eapol_test opens the RadSec connection itself, with hostapd's RADIUS client
# (the implementation family the UniFi APs use: hostapd on OpenSSL 1.1.1t),
# the lab AP certificate and an AP's TLS offer (see cl-ap-*.cnf in lab_setup).
# The first ClientHello in its log is the RadSec one; EAP starts only once the
# RadSec connection is up. EAP-TLS completing over it is the definitive check
# that an accepted RadSec connection carries RADIUS, and src= records the AP's
# own address.
test_both_radsec_registered_device_gets_its_vlan() {
    local id=client-device-01 groups="X25519,P-256,X448,P-521,P-384" line i
    [ "${MODE}" = pqc ] && { id=anonymous; groups="${groups},X25519MLKEM768"; }
    eap dev01 "${id}" --via-radsec
    expect_eq "$(offered_versions)" "TLS 1.3,TLS 1.2" "RadSec client offered the AP's TLS versions"
    expect_eq "$(offered_tls13_suites)" "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256" "RadSec client offered the AP's TLS 1.3 cipher suites"
    expect_eq "$(offered_groups)" "${groups}" "RadSec client offered the AP's groups"
    expect_eq "$(offered_key_shares)" "X25519" "RadSec client sent the AP's key share (the server must ask for P-384)"
    expect_eq "$(grep -c 'RADIUS: TLS connection established' "${EAP_OUT}")" "1" "RadSec connection established"
    expect_accept 10 client-device-01
    for i in $(seq 20); do
        line=$(server_log | grep 'EAP-TLS admitted' | grep -F " src=${AP_IP} " | tail -n1)
        [ -n "${line}" ] && break
        sleep 0.25
    done
    expect_eq "$(echo "${line}" | sed -nE 's/.* cn="([^"]*)".*/\1/p')" "client-device-01" \
        "admission logged with the AP's address (src=${AP_IP})"
}

# The APs' shared certificate CN (lab-aps) has an authorize entry, VLAN 99. A
# policy keyed on the authenticator's certificate instead of the device's
# would admit this unregistered device, or give a registered one VLAN 99.
test_both_radsec_vlan_never_comes_from_the_ap_certificate() {
    eap dev99 client-device-99 --via-radsec; expect_reject
    eap dev02 client-device-02 --via-radsec; expect_accept 30 client-device-02
}

# The client offers everything: TLS 1.2 and 1.3, OpenSSL's default cipher
# suites and groups (key shares for X25519MLKEM768 and X25519 first). The
# server must choose CNSA 1.0, not merely accept it.
test_both_radsec_negotiates_exactly_cnsa_1_0() {
    radsec_connect ap
    expect_radsec_accepted
}

test_both_radsec_tls12_is_rejected() {
    radsec_connect ap -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384
    expect_radsec_refused 'Alert write:fatal:protocol version'
}

test_both_radsec_non_cnsa_cipher_suites_are_rejected() {
    radsec_connect ap -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256
    expect_radsec_refused 'Alert write:fatal:handshake failure'
}

# Includes a hybrid ML-KEM group, because strict CNSA 1.0 allows only P-384.
# Refusing ML-KEM here is a temporary limit of the APs, not a goal: their
# RadSec client (hostapd on UniFi firmware 6.8.2) offers no ML-KEM group. A
# hybrid ML-KEM group on this link would improve security against quantum
# attackers: the Wi-Fi session keys (MS-MPPE) travel over RadSec, so someone
# recording the link today could decrypt them, and then the Wi-Fi traffic
# they protect, once a quantum computer exists. A hybrid group would keep
# P-384's classical protection too. When an AP firmware update offers one,
# switch the RadSec ecdh_curve to it (preferably SecP384r1MLKEM1024) and
# update this test in the same change.
test_both_radsec_non_cnsa_groups_are_rejected() {
    radsec_connect ap -groups X25519:P-256:X25519MLKEM768
    expect_radsec_refused 'Alert write:fatal:handshake failure'
}

# ap_p256 matches ap in everything (CA, CN) except its P-256 key. ap runs first
# as a control, so the refusal can only be for the key.
test_both_radsec_client_signature_other_than_p384_is_rejected() {
    radsec_connect ap; expect_radsec_accepted
    radsec_connect ap_p256; expect_radsec_refused 'Alert write:fatal'
}

# Only the 192-bit security level (@SECLEVEL=4) checks the signature ON the
# AP's certificate
test_both_radsec_client_certificate_signed_with_sha256_is_rejected() {
    radsec_connect ap_sha256
    expect_radsec_refused 'error 68 : CA signature digest algorithm too weak'
}

test_both_radsec_requires_a_client_certificate() {
    radsec_connect none
    expect_radsec_refused 'Alert write:fatal'
}

# A Wi-Fi device certificate (user CA) must never open a RadSec connection.
# Refused by the trust anchor (authenticators-ca.pem only) and, failing that,
# by the issuer pin (check_cert_issuer).
test_both_radsec_refuses_device_certificates() {
    radsec_connect dev01
    expect_radsec_refused 'Alert write:fatal'
}

test_both_radsec_refuses_certificates_from_an_untrusted_ca() {
    radsec_connect other
    expect_radsec_refused 'Alert write:fatal:unknown CA'
}

# Only addresses in the 'radsec' client list may connect, even with a valid AP
# certificate. FreeRADIUS checks the source address when it accepts the TCP
# connection and closes it before any TLS. The same certificate from the AP
# subnet runs first as a control.
test_both_radsec_refuses_connections_from_unlisted_addresses() {
    radsec_connect ap; expect_radsec_accepted
    RADSEC_FROM=outside radsec_connect ap
    expect_eq "$(echo "${RADSEC_OUT}" | grep -c '^New, TLSv')" "0" "client: no TLS session from an unlisted address"
    expect_radsec_refused "unknown client ${OUT_CLIENT_IP} port [0-9]+ proto tcp"
}

# ==============================================================================
# Functional tests: classical server
# ==============================================================================

# dev01p256 matches dev01 in everything (CA, CN, authorize entry) except its
# P-256 key. dev01 runs first as a control; the P-256 copy must then be
# refused during the TLS handshake, before the admission policy is reached.
test_both_client_signature_other_than_p384_is_rejected() {
    local before i alert='Alert write:fatal'
    eap dev01 client-device-01; expect_accept 10 client-device-01
    before=$(server_log | grep -c "${alert}")
    eap dev01p256 client-device-01; expect_reject
    for i in $(seq 20); do
        [ "$(server_log | grep -c "${alert}")" -gt "${before}" ] && break
        sleep 0.25
    done
    expect_eq "$(( $(server_log | grep -c "${alert}") - before ))" "1" "one TLS handshake failure logged by the server"
}

# dev01sha256 matches dev01 in everything except the CA's signature on it,
# made with SHA-256 instead of SHA-384. The signatures *on* certificates are
# not covered by sigalgs_list (which governs handshake signatures); this
# checks they are held to CNSA strength too.
test_both_client_certificate_signed_with_sha256_is_rejected() {
    local before i alert='Alert write:fatal'
    eap dev01 client-device-01; expect_accept 10 client-device-01
    before=$(server_log | grep -c "${alert}")
    eap dev01sha256 client-device-01; expect_reject
    for i in $(seq 20); do
        [ "$(server_log | grep -c "${alert}")" -gt "${before}" ] && break
        sleep 0.25
    done
    expect_eq "$(( $(server_log | grep -c "${alert}") - before ))" "1" "one TLS handshake failure logged by the server"
}

# In TLS 1.2 the signature algorithm fixes the hash, not the curve: a P-384
# device willing to sign only with SHA-256 must be refused. (In TLS 1.3 a
# P-384 key cannot sign with SHA-256 at all, so this case only exists here.)
test_classical_client_signature_with_sha256_is_rejected() {
    local before i alert='Alert write:fatal'
    before=$(server_log | grep -c "${alert}")
    eap dev01 client-device-01 --groups sigalgs-sha256; expect_reject
    for i in $(seq 20); do
        [ "$(server_log | grep -c "${alert}")" -gt "${before}" ] && break
        sleep 0.25
    done
    expect_eq "$(( $(server_log | grep -c "${alert}") - before ))" "1" "one TLS handshake failure logged by the server"
}

test_classical_claimed_identity_must_equal_certificate_cn() {
    eap dev02 client-device-01; expect_reject
    eap dev02 anonymous; expect_reject
    eap dev02 CLIENT-DEVICE-02; expect_reject
}

test_classical_tls13_is_rejected() {
    eap dev01 client-device-01 --tls tls13; expect_reject
}

# ==============================================================================
# Functional tests: post-quantum server
# ==============================================================================

test_pqc_vlan_comes_from_certificate_not_claimed_identity() {
    eap dev02 client-device-01; expect_accept 30 client-device-02
    eap dev01 client-device-02; expect_accept 10 client-device-01
}

test_pqc_tls12_is_rejected() {
    eap dev01 anonymous --tls tls12; expect_reject
}

# Each TLS 1.3 cipher suite offered on its own. Every case first checks the
# client's ClientHello, so it provably offered what the case claims; accepted
# sessions are checked from both ends, and rejections must be for the cipher
# suite, not for some unrelated reason.
test_pqc_aes256_offered_alone_is_accepted_and_used() {
    eap dev01 anonymous --groups suite-TLS_AES_256_GCM_SHA384
    expect_eq "$(offered_tls13_suites)" "TLS_AES_256_GCM_SHA384" "client offered"
    expect_accept 10
    expect_negotiated "TLS 1.3" TLS_AES_256_GCM_SHA384
}

test_pqc_every_other_tls13_cipher_suite_is_rejected() {
    local suite before rejected=0 i alert='Alert write:fatal:handshake failure'
    before=$(server_log | grep -c "${alert}")
    for suite in "${TLS13_SUITES[@]}"; do
        [ "${suite}" = TLS_AES_256_GCM_SHA384 ] && continue
        eap dev01 anonymous --groups "suite-${suite}"
        expect_eq "$(offered_tls13_suites)" "${suite}" "client offered"
        expect_reject
        rejected=$((rejected + 1))
    done
    # Each rejection must be a failed TLS handshake (no cipher suite in common),
    # not a later refusal by the admission policy. radiusd's own log lines can
    # arrive late, so wait briefly for them.
    for i in $(seq 20); do
        [ "$(server_log | grep -c "${alert}")" -ge $((before + rejected)) ] && break
        sleep 0.25
    done
    expect_eq "$(( $(server_log | grep -c "${alert}") - before ))" "${rejected}" \
        "one TLS handshake failure logged by the server per rejected suite"
}

test_pqc_client_offering_every_cipher_suite_gets_aes256() {
    eap dev01 anonymous --groups suite-all
    expect_eq "$(offered_tls13_suites)" "$(IFS=,; echo "${TLS13_SUITES[*]}")" "client offered"
    expect_accept 10
    expect_negotiated "TLS 1.3" TLS_AES_256_GCM_SHA384
}

test_pqc_client_offering_tls12_and_tls13_gets_tls13() {
    eap dev01 anonymous --tls tls12or13
    expect_accept 10
    expect_negotiated "TLS 1.3" TLS_AES_256_GCM_SHA384
}

test_pqc_accepts_each_hybrid_group() {
    eap dev01 anonymous --groups x25519mlkem768
    expect_eq "$(offered_groups)" "X25519MLKEM768" "client offered"
    expect_accept 10
    eap dev01 anonymous --groups secp384r1mlkem1024
    expect_eq "$(offered_groups)" "SecP384r1MLKEM1024" "client offered"
    expect_accept 10
}

# Each classical key exchange group offered on its own, P-384 included: it is
# the one group a weakened configuration would most plausibly fall back to
# (SUITEB192 in cipher_list, for one, replaces ecdh_curve with P-384). Each
# rejection must be a failed TLS handshake, not a later refusal.
test_pqc_every_classical_key_exchange_group_is_rejected() {
    local group before rejected=0 i alert='Alert write:fatal'
    before=$(server_log | grep -c "${alert}")
    for group in "${CLASSICAL_GROUPS[@]}"; do
        eap dev01 anonymous --groups "group-${group}"
        expect_eq "$(offered_groups)" "${group}" "client offered"
        expect_reject
        rejected=$((rejected + 1))
    done
    for i in $(seq 20); do
        [ "$(server_log | grep -c "${alert}")" -ge $((before + rejected)) ] && break
        sleep 0.25
    done
    expect_eq "$(( $(server_log | grep -c "${alert}") - before ))" "${rejected}" \
        "one TLS handshake failure logged by the server per rejected group"
}

# A realm in the (untrusted) outer identity must not change how the request
# is handled: it should be authenticated locally by certificate like any other
test_pqc_realm_suffix_does_not_change_handling() {
    eap dev02 client-device-02@example.com; expect_accept 30 client-device-02
}

# ==============================================================================
# Log checks, run after each server's functional tests
# ==============================================================================

check_logs_record_every_admission_and_no_secrets() {
    local log="${WORK}/${MODE}-server.log"
    server_log > "${log}"
    expect_no_match "${log}" 'MS-MPPE|Recv-Key|Send-Key' "server log must not contain session keys"
    expect_no_match "${log}" "${AUTH_SECRET}|${TEST_SECRET}" "server log must not contain shared secrets"
    expect_eq "$(grep -c 'EAP-TLS admitted' "${log}")" "${EAP_SUCCESSES}" \
        "one 'EAP-TLS admitted' line per successful authentication"
}

# ==============================================================================
# Main
# ==============================================================================
echo "=============================================================================="
echo "  EAP-TLS guarantee tests"
echo "=============================================================================="
echo "Static tests"
MODE=""
run_group test_static_

if [ "${STATIC_ONLY}" = false ]; then
    lab_setup
    echo ""
    echo "Image tests (${RADIUS_IMAGE})"
    run_group test_image_
    for MODE in classical pqc; do
        echo ""
        echo "Functional tests: ${MODE} server"
        start_server "${MODE}"
        run_group test_both_
        run_group "test_${MODE}_"
        run_test check_logs_record_every_admission_and_no_secrets
    done
fi

echo ""
echo "=============================================================================="
printf '  %d passed, %d failed, %d skipped\n' "${PASSED}" "${FAILED}" "${SKIPPED}"
for t in ${FAILED_NAMES[@]+"${FAILED_NAMES[@]}"}; do printf '  ✗ %s\n' "${t}"; done
echo "=============================================================================="
exit "${FAILED}"
