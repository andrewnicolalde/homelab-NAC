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
├── eap                      # Custom EAP parameters (if overriding)
└── certs/
    ├── root_ca.crt
    ├── server.crt
    ├── server.key
    ├── ca.pem
    └── server.pem
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

# Replace the base ConfigMap with your actual private network definitions:
configMapGenerator:
  - name: freeradius-config
    behavior: replace
    files:
      - clients.conf=./clients.conf
      - eap=./eap
      - authorize=./authorize

# Replace the base Secret with your actual PKI certificates and private keys:
secretGenerator:
  - name: freeradius-certs
    behavior: replace
    files:
      - ca.crt=./certs/root_ca.crt
      - server.crt=./certs/server.crt
      - server.key=./certs/server.key
      - ca.pem=./certs/ca.pem
      - server.pem=./certs/server.pem
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
2. Configure your server IP and identities:
   ```bash
   RADIUS_IP="10.50.0.100"
   CLIENT_IDENTITY="client-device-01"
   ROOT_CA_NAME="Enterprise Root CA"
   ```
3. Run `generate-certs.sh` (or pass parameters directly: `./generate-certs.sh 10.50.0.100 client-device-01`). The generator automatically sources `certs.env` if present.

