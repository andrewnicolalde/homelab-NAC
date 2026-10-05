# Automated EAP-TLS & CNSA Suite B 192-bit Validation

This directory provides an automated, containerized test harness using `eapol_test` (from `wpa_supplicant`) to validate the FreeRADIUS deployment before touching physical Wi-Fi hardware.

---

## What `eapol_test` Validates

`eapol_test` encapsulates IEEE 802.1X EAP packets inside standard RADIUS UDP packets and transmits them directly to FreeRADIUS, acting simultaneously as the client supplicant (`client-device-01`) and the NAS/AP.

### Validated at this stage (No Wi-Fi required):
1. **CNSA Suite B 192-bit Compliance:**
   - Enforces TLS 1.2 with `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.
   - Rejects non-CNSA cipher suites, non-P-384 curves, and SHA-256 signatures.
   - Verifies the full P-384 ECDSA certificate chain (Root CA -> Server Cert and Root CA -> Client Cert).
2. **EAP-TLS Handshake:**
   - Validates mutual authentication without session tickets or resumption caching.
3. **Dynamic VLAN Assignment (RFC 3580):**
   - Asserts that FreeRADIUS returns:
     - `Tunnel-Type = VLAN (13)`
     - `Tunnel-Medium-Type = IEEE-802 (6)`
     - `Tunnel-Private-Group-Id = "10"`

### What requires physical Wi-Fi (Cannot be tested via `eapol_test`):
- **Over-the-Air L2 Encryption:** The 802.11 4-Way Handshake negotiating GCMP-256 pairwise frame encryption and BIP-GMAC-256 Protected Management Frames (PMF) between the AP's radio hardware and the Apple device's Wi-Fi chip.

---

## Prerequisites

1. **Local Container Runtime:** `podman` or `docker` installed on your machine.
2. **Certificates Generated:** `ca.pem`, `client.crt`, and `client.key` present in `certificate-authority/`, or in the directory given by `CERTS_DIR`:
   - `ca.pem`: RADIUS Server Root CA (`radius-server/server_root_ca.crt`), used to verify the server
   - `client.crt` / `client.key`: client identity, extracted from its PKCS#12 bundle:
     ```bash
     openssl pkcs12 -legacy -in client-device-01.p12 -clcerts -nokeys -out "$CERTS_DIR/client.crt"
     openssl pkcs12 -legacy -in client-device-01.p12 -nocerts -noenc -out "$CERTS_DIR/client.key"
     ```
3. **FreeRADIUS Client Authorized:** 
   FreeRADIUS drops packets from unknown IP addresses. If running the test from your workstation (e.g. `10.10.10.x`), ensure your workstation (or the subnet it's on) is permitted in `k8s/config/clients.conf`:
   ```text
   client workstation_test {
       ipaddr = 10.10.10.0/24
       secret = 'YOUR_STRONG_48_CHAR_SECRET'
       require_message_authenticator = yes
       nas_type = other
   }
   ```

---

## How to Run

Execute the automated test script:

```bash
./test/run-test.sh
```

The script automatically detects your secret in this order of precedence:
1. Positional argument: `./test/run-test.sh <SERVER> <PORT> <SECRET>`
2. Environment variable: `export RADIUS_SECRET='...'`
3. Local unversioned file: `.radius_secret` in the repository root
4. Local unversioned config: `k8s/config/clients.conf`

### Custom Server / Port / Secret

You can override target parameters via positional arguments:

```bash
./test/run-test.sh <SERVER_IP> <PORT> <SECRET> <CONFIG_FILE>

# Example:
./test/run-test.sh 10.50.0.100 31812 "$RADIUS_SECRET" eapol_test.conf
```

---

## Guarantee Tests (`guarantees.sh`)

`run-test.sh` checks one live authentication. `guarantees.sh` checks that every property the setup relies on holds, for both the classical and the post-quantum deployment. Each `test_*` function is named after the guarantee it checks.

| Layer | What it checks | Needs |
|---|---|---|
| `test_static_*` | The repository's configuration and manifests: the admission policy is wired into both servers and fails closed, the certificate lookup uses the verified CN, TLS versions, groups and suites, session resumption, Message-Authenticator and secrets in `clients.conf`, logging, container hardening, image pinning, overlay `merge` behaviour | bash only |
| `test_image_*` | The stock configuration inside the pinned FreeRADIUS image | podman or docker |
| `test_both_*`, `test_classical_*`, `test_pqc_*` | Real authentications against each server in a disposable lab: registered, unregistered, expired, untrusted-CA and missing certificates; identity binding; TLS version, group and suite policy; password-based methods; wrong shared secret; re-authentication; RadSec (see below); and afterwards, that the log has one line per admission and no keys or secrets | podman or docker, the `eapol-test:pqc` image |

The lab uses the Deployment's pinned image and `radiusd` arguments with the repository's own `eap`, `check-eap-tls`, `cert_vlan`, `cert_log` and `clients.conf.example`, and a throwaway PKI generated for each run. Nothing real is used.

```bash
./test/guarantees.sh --static        # configuration only, in seconds
./test/guarantees.sh                 # everything, about 90 seconds
./test/guarantees.sh --only pqc      # tests whose name matches a regex

# Also check a private overlay's clients.conf, authorize and kustomization.yaml
PRIVATE_CONFIG_DIR=../homelab-network-private ./test/guarantees.sh --static
```

The exit status is the number of failed tests. Set `RADIUS_IMAGE` if the pinned digest is not available locally.

**RadSec (`test_both_radsec_*`).** Each lab server also runs the RadSec listener (`k8s/config/radsec`) with a lab authenticator CA. Two kinds of client test it:
- **`eapol_test` stands in for an access point.** The UniFi APs' RadSec client is hostapd (`wpad`) on OpenSSL 1.1.1t. `eapol_test`, built with `CONFIG_RADIUS_TLS=y`, uses hostapd's RADIUS client to open the RadSec connection itself (`-X TLS`, port 2083, the lab AP certificate), and is configured to send what a UniFi AP sends: TLS 1.3 and 1.2, AES-256-GCM and AES-128-GCM, the groups x25519, P-256, x448, P-521, P-384 in that order, and a key share for x25519 only, so the server must ask for P-384. The test decodes the ClientHello actually sent to check that. EAP-TLS over the connection proves an accepted RadSec connection really carries RADIUS: a registered device gets its VLAN, logged with the client's address as `src=`. The APs' shared certificate CN also has an `authorize` entry, so the tests also prove the VLAN never comes from the AP's certificate. Two differences remain from a real AP: OpenSSL 3.5 also lists ML-DSA and brainpool signature algorithms, which 1.1.1 does not; and on the post-quantum server the client's group list ends with X25519MLKEM768, because one OpenSSL configuration covers both of `eapol_test`'s roles and the device needs it. The RadSec listener ignores both.
- **`openssl s_client`** checks the TLS policy directly: a client offering everything gets exactly TLS 1.3, `TLS_AES_256_GCM_SHA384`, P-384 and `ecdsa_secp384r1_sha384`, while TLS 1.2, other cipher suites, other groups (including hybrid ML-KEM), a P-256 or SHA-256-signed AP certificate, no certificate, a device certificate and an untrusted CA are all refused. So is a valid AP certificate from an address outside the `radsec` client list: the lab server is also attached to a second network for this, and FreeRADIUS must close the connection before any TLS (`unknown client`). In TLS 1.3 the server checks the client certificate only after the client's Finished, and FreeRADIUS drops a refused connection without the client ever receiving the alert. So each client holds the connection open for 2 seconds, and the verdict, with its reason, is read from the server's log.

The post-quantum server's TLS 1.3 cipher-suite tests offer each suite on its own, plus all of them at once. Its key exchange tests likewise offer each hybrid group, and each classical group (X25519, X448, P-256, P-384, P-521), on its own; the classical ones must all be refused. Each case first decodes the client's own ClientHello (its cipher suites or supported groups), to prove it offered what the case claims. Accepted sessions are checked from both ends: the client's view comes from the ServerHello it received, the server's from its `cert_log` line. A rejection only counts if the server logged a failed TLS handshake, so a refusal for some unrelated reason can't pass as one.

### Mutation Check (`mutation-check.sh`)

A passing test only means something if it fails when the setting it guards is broken. `mutation-check.sh` copies the repository to a temporary directory and deliberately weakens one setting in the copy's `eap` configuration at a time: it removes or widens `cipher_suites`, prefers AES-128, allows TLS 1.2, removes `sigalgs_list` or `@SECLEVEL=4`, adds P-256 to the classical server's `ecdh_curve`, or puts OpenSSL's `SUITEB192` keyword at the start of the PQC server's `cipher_list` (which replaces its hybrid groups with classical P-384 and discards `@SECLEVEL=4`). One mutation also removes the SSID split from `check-eap-tls`, which the SSID logging test must catch. The RadSec listener gets the same treatment: allowing TLS 1.2, ChaCha20 or a hybrid ML-KEM group, removing `@SECLEVEL=4`, `sigalgs_list` or `require_client_cert`, trusting the user-device CA, and widening the `radsec` client list to every address. It then checks that the tests guarding that setting fail. The working tree is never modified.

```bash
./test/mutation-check.sh                  # every mutation, a few minutes
./test/mutation-check.sh --only cipher    # mutations whose name matches a regex
```

Some properties are enforced by two settings at once. Weakening one of them must then *not* change behaviour: the script checks that the guarding test still passes, and that it fails once the other control is weakened too. The static tests pin each setting itself.

| Property | Enforced by |
|---|---|
| PQC server refuses TLS 1.2 | `tls_min_version = "1.3"`, and the hybrid ML-KEM groups, which exist only in TLS 1.3 |
| PQC server refuses TLS 1.3 AES-128 suites | `cipher_suites`, and `@SECLEVEL=4` (AES-128 offers 128 bits). ChaCha20 (256-bit key) passes level 4, so `cipher_suites` alone excludes it |
| Devices with keys on other curves (P-256) are refused | `@SECLEVEL=4` on both servers, plus `sigalgs_list` on the PQC server (TLS 1.3 signature schemes name the curve) and `ecdh_curve = "secp384r1"` on the classical server (TLS 1.2 checks certificate keys against the group list; its signature algorithms don't name the curve) |
| ECDSA signatures with SHA-256 in a TLS 1.2 handshake are refused | `sigalgs_list` and `@SECLEVEL=4` |
| Certificates signed with SHA-256 are refused | `@SECLEVEL=4` only: `sigalgs_list` governs the signatures made in the handshake, not those on certificates |
| RadSec refuses P-256 AP certificates | `sigalgs_list` and `@SECLEVEL=4` in `k8s/config/radsec` |
| RadSec refuses device certificates | the trust anchor (`ca_file`, the authenticator CA only) and the issuer pin (`check_cert_issuer`) |

---

## Observing Server Logs in Real Time

In a separate terminal window, monitor the FreeRADIUS logs:

```bash
kubectl logs -n freeradius-experimentation -l app=freeradius -f
```

FreeRADIUS runs without debug output, because every debug level prints the MS-MPPE session keys of each Access-Accept. The log shows startup messages, errors (such as TLS handshake failures and packets with the wrong shared secret) and one line per EAP-TLS admission decision from `k8s/config/cert_log`:

```text
... : Auth: EAP-TLS admitted: cn="client-device-01" serial=... issuer="/CN=Enterprise Root CA" vlan=10 mac=02-00-00-00-00-01 nas="" called="" ssid="" tls="TLS 1.2" cipher=ECDHE-ECDSA-AES256-GCM-SHA384
... : Auth: EAP-TLS rejected, no authorize entry for certificate: cn="..." ...
```

To troubleshoot with full debug output, temporarily switch the Deployment to `-X`, then re-apply your overlay to switch it back. The debug output includes session keys, so treat those logs as secret:

```bash
kubectl -n freeradius-experimentation patch deployment freeradius-test --type=json \
  -p '[{"op":"replace","path":"/spec/template/spec/containers/0/args","value":["-X"]}]'
```

---

## Over-the-Air Physical Wi-Fi Verification (CNSA 1.0 Proof)

To verify with 100% certainty that the physical Access Point and client are operating in **strict WPA3-Enterprise 192-bit (CNSA 1.0 / Suite B)** mode:

### 1. Local Client Verification (macOS)
Inspect the active interface status without `sudo`:

```bash
ipconfig getsummary en0 | grep -i security
```

Output:
```text
  Security : SHA384_8021X
```
*(In macOS networking, `SHA384_8021X` corresponds directly to IEEE 802.11 AKM 12: 802.1X with SHA-384).*

### 2. Over-the-Air RSN Information Element Proof
Capturing raw 802.11 beacon frames off the airwaves (e.g. using macOS Wireless Diagnostics Sniffer or an AP capture) and dissecting the IEEE 802.11 RSN Information Element via `tshark`:

```bash
tshark \
  -r ./wifi_cnsa_capture.pcap \
  -Y "wlan.rsn.akms.type == 12" -V | grep -A 22 "Tag: RSN Information" | head -n 23

        Tag: RSN Information
            Tag Number: RSN Information (48)
            Tag length: 26
            RSN Version: 1
            Group Cipher Suite: 00:0f:ac (Ieee 802.11) GCMP (256)
                Group Cipher Suite OUI: 00:0f:ac (Ieee 802.11)
                Group Cipher Suite type: GCMP (256) (9)
            Pairwise Cipher Suite Count: 1
            Pairwise Cipher Suite List 00:0f:ac (Ieee 802.11) GCMP (256)
                Pairwise Cipher Suite: 00:0f:ac (Ieee 802.11) GCMP (256)
                    Pairwise Cipher Suite OUI: 00:0f:ac (Ieee 802.11)
                    Pairwise Cipher Suite type: GCMP (256) (9)
            Auth Key Management (AKM) Suite Count: 1
            Auth Key Management (AKM) List 00:0f:ac (Ieee 802.11) WPA (SHA384-SuiteB)
                Auth Key Management (AKM) Suite: 00:0f:ac (Ieee 802.11) WPA (SHA384-SuiteB)
                    Auth Key Management (AKM) OUI: 00:0f:ac (Ieee 802.11)
                    Auth Key Management (AKM) type: WPA (SHA384-SuiteB) (12)
            RSN Capabilities: 0x00c0
                .... .... .... ...0 = RSN Pre-Auth capabilities: Transmitter does not support pre-authentication
                .... .... .... ..0. = RSN No Pairwise capabilities: Transmitter can support WEP default key 0 simultaneously with Pairwise key
                .... .... .... 00.. = RSN PTKSA Replay Counter capabilities: 1 replay counter per PTKSA/GTKSA/STAKeySA (0x0)
                .... .... ..00 .... = RSN GTKSA Replay Counter capabilities: 1 replay counter per PTKSA/GTKSA/STAKeySA (0x0)
                .... .... .1.. .... = Management Frame Protection Required: Required
```

#### What This Confirms:
* **AKM Suite (`00:0f:ac:12`):** `Auth Key Management (AKM) type: WPA (SHA384-SuiteB) (12)`.
* **Data Encryption (`00:0f:ac:9`):** Both Pairwise and Group ciphers are strictly `GCMP (256)`.
* **Strict Non-Transition Mode:** Suite counts are `1`, guaranteeing no fallback to CCMP-128 or legacy AKMs is permitted.
* **Management Frame Protection:** `Management Frame Protection Required: Required` (mandatory PMF).

