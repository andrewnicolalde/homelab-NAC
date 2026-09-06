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
