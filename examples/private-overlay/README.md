# Private Overlay Pattern for Homelab Deployments

This directory demonstrates how to version-control your site-specific network configuration (real VLANs, client device identities, AP RADIUS secrets, and CA certificates) in a **separate, private Git repository** while consuming the public manifests from this repository.

---

## Directory Structure in your Private Repository

In your separate private repository (e.g. `homelab-network-private`), set up a directory like this:

```text
homelab-network-private/
├── kustomization.yaml       # Defines resources and generators
├── clients.conf             # Real AP & switch IP ranges; secrets referenced as $ENV{...}
├── .radius_secret           # RADIUS shared secrets, KEY=value (gitignore this file!)
├── authorize                # Real device names mapped to production VLANs
└── certs/
    ├── radius-server/
    │   ├── server_root_ca.crt
    │   └── server.pem
    ├── user-client-devices/
    │   ├── user_root_ca.crt
    │   └── <device-name>/
    │       └── <device-name>.p12
    └── network-infrastructure-authenticators/
        ├── authenticators_root_ca.crt
        ├── authenticator.crt
        └── authenticator.key
```

---

## Private `kustomization.yaml` Example

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: freeradius-experimentation

resources:
  # Pull the base Kubernetes manifests directly from the public GitHub repository:
  - github.com/andrewnicolalde/homelab-NAC//k8s?ref=main

# Override the site-specific keys of the base ConfigMap. Use merge, not
# replace: the base also ships eap and the shared admission policy
# (check-eap-tls, cert_vlan, cert_log), and radiusd will not start without them.
configMapGenerator:
  - name: freeradius-config
    behavior: merge
    files:
      - clients.conf=./clients.conf
      - authorize=./authorize

# Replace the base Secrets with your RADIUS shared secrets and your actual
# PKI certificates and private keys:
secretGenerator:
  # RADIUS client shared secrets from a gitignored KEY=value file; clients.conf
  # references them as $ENV{RADIUS_SECRET_AUTHENTICATORS} / $ENV{RADIUS_SECRET_TEST}
  - name: freeradius-client-secrets
    behavior: replace
    envs:
      - .radius_secret
  - name: freeradius-certs
    behavior: replace
    files:
      - server.pem=./certs/radius-server/server.pem
      - ca.pem=./certs/user-client-devices/user_root_ca.crt
```

### RADIUS shared secrets

Shared secrets are kept out of version control entirely. `clients.conf` references them as environment variables, and the Deployments load those from the `freeradius-client-secrets` Secret:

```text
# clients.conf
client network_authenticators {
    ipaddr = 10.1.0.0/24
    secret = $ENV{RADIUS_SECRET_AUTHENTICATORS}
    ...
}
```

```text
# .radius_secret  (add it to .gitignore; KEY=value, one per line)
RADIUS_SECRET_AUTHENTICATORS=<random value, also entered in your AP RADIUS profile>
RADIUS_SECRET_TEST=<random value, used by test/run-test.sh>
```

Generate each value with `openssl rand -base64 64 | tr -dc 'A-Za-z0-9' | head -c 48` (48 random alphanumeric characters, about 286 bits; removing the two base64 symbols keeps the remaining characters uniformly distributed), and use a different secret per client. Check your authenticator's limits: UniFi is known to accept 48 alphanumeric characters. FreeRADIUS refuses to start if a referenced variable is unset or empty. The `envs:` file format never includes the line ending in a value, so an editor-added trailing newline cannot silently change a secret.

---

## Deploying

From your private repository:

```bash
# Preview the generated manifests with your private secrets populated:
kubectl kustomize .

# Apply directly to your Kubernetes cluster:
kubectl apply -k .
```

---

## Certificate Generation Configuration

To configure site-specific parameters when generating certificates:
1. Copy `certs.env.example` to `certs.env` in your private repository.
2. Configure your server hostname and identities:
   ```bash
   RADIUS_SERVER_NAME="radius.internal.example.com"
   ROOT_CA_NAME="Enterprise Root CA"
   ```
3. Run `./generate-certs.sh --full-with-defaults` for the complete bootstrap, or `./generate-certs.sh --client client-device-02` to issue credentials for a new device. The generator automatically sources `certs.env` if present.

