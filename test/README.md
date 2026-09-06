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
     - `Tunnel-Private-Group-Id = "80"`

### What requires physical Wi-Fi (Cannot be tested via `eapol_test`):
- **Over-the-Air L2 Encryption:** The 802.11 4-Way Handshake negotiating GCMP-256 pairwise frame encryption and BIP-GMAC-256 Protected Management Frames (PMF) between the AP's radio hardware and the Apple device's Wi-Fi chip.

---

## Prerequisites

1. **Local Container Runtime:** `podman` or `docker` installed on your machine.
2. **Certificates Generated:** `ca.pem`, `client.crt`, and `client.key` present in `certificate-authority/`.
3. **FreeRADIUS Client Authorized:** 
   FreeRADIUS drops packets from unknown IP addresses. If running the test from your workstation (e.g. `10.10.10.x`), ensure your workstation (or the subnet it's on) is permitted in `k8s/config/clients.conf`:
   ```text
   client workstation_test {
       ipaddr = 10.10.10.69/32
       secret = 'REPLACE_WITH_STRONG_48_CHAR_SECRET'
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

### Custom Server / Port / Secret

You can override target parameters via positional arguments:

```bash
./test/run-test.sh <SERVER_IP> <PORT> <SECRET> <CONFIG_FILE>

# Example:
./test/run-test.sh 10.50.0.100 31812 'REPLACE_WITH_TEST_SECRET_64_CHAR' eapol_test.conf
```

---

## Observing Server Logs in Real Time

In a separate terminal window, monitor FreeRADIUS debugging logs:

```bash
kubectl logs -n freeradius-experimentation -l app=freeradius -f
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
andrew@client-device-01 Developer/talos-k8s-cluster » /Applications/Wireshark.app/Contents/MacOS/tshark \
  -r ~/Desktop/client-device-01_ch36_2026-09-06_22.41.07.961.pcap \
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

