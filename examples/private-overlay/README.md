# Private Overlay Pattern for Homelab Deployments

This directory demonstrates how to version-control your site-specific network configuration (real VLANs, client device identities, AP RADIUS secrets, and CA certificates) in a **separate, private Git repository** while consuming the public manifests from this repository.

---

## Directory Structure in your Private Repository

In your separate private repository (e.g. `homelab-network-private`), set up a directory like this:

```text
homelab-network-private/
├── kustomization.yaml       # Defines resources and generators
├── clients.conf             # Real AP & Switch IP ranges and RADIUS secrets
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
# replace: the base also ships eap and the shared check-eap-tls/cert_vlan
# admission policy, and radiusd will not start without them.
configMapGenerator:
  - name: freeradius-config
    behavior: merge
    files:
      - clients.conf=./clients.conf
      - authorize=./authorize

# Replace the base Secret with your actual PKI certificates and private keys:
secretGenerator:
  - name: freeradius-certs
    behavior: replace
    files:
      - server.pem=./certs/radius-server/server.pem
      - ca.pem=./certs/user-client-devices/user_root_ca.crt
```

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

