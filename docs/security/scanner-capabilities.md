# Scanner capabilities and deployment guidance

## Required Linux capabilities

The ForgeScan network scanner uses raw sockets for SYN scanning, ICMP probes, and OS fingerprinting. This requires specific Linux capabilities:

| Capability | Why needed | What happens without it |
|-----------|------------|------------------------|
| `NET_RAW` | TCP SYN scan (half-open), ICMP echo, raw packet construction | Falls back to TCP connect scan (full handshake, slower, more visible to IDS) |
| `NET_ADMIN` | Network interface configuration, promiscuous mode for passive monitoring | Passive monitoring and ARP scanning disabled; active scanning still works |

**Recommendation:** Grant `NET_RAW` and `NET_ADMIN` only to the network scanner. Web application and cloud scanners do not need these capabilities and should run with all capabilities dropped.

### Graceful degradation

The scanner detects available capabilities at startup. If raw sockets are unavailable, it automatically falls back to TCP connect scanning. This is fully functional but:
- Completes the full TCP handshake (SYN → SYN-ACK → ACK → RST)
- Is slower than SYN scanning
- Leaves connection entries in target system logs
- Cannot perform OS fingerprinting via TCP/IP stack analysis

## Scope guardrails

The scanner enforces target scope rules before any network activity. Configure these in the `[scope]` section of `scanner.toml` or via environment variables.

### Configuration

```toml
[scope]
# Positive allowlist — if non-empty, ONLY these ranges can be scanned
allowed_cidrs = ["10.0.0.0/8", "172.16.0.0/12"]

# Additional deny entries (appended to built-in deny list)
denied_cidrs = ["10.0.0.1/32"]
denied_hostnames = ["admin-panel.internal"]

# Emergency kill switch
emergency_disable = false

# Hard cap on targets per scan task
max_targets_per_scan = 10000
```

### Built-in deny list

The following ranges are always denied (cannot be overridden):

| Range | Reason |
|-------|--------|
| `127.0.0.0/8` | IPv4 loopback |
| `169.254.0.0/16` | IPv4 link-local (includes AWS/Azure metadata at 169.254.169.254) |
| `224.0.0.0/4` | IPv4 multicast |
| `240.0.0.0/4` | IPv4 reserved |
| `::1/128` | IPv6 loopback |
| `fe80::/10` | IPv6 link-local |
| `ff00::/8` | IPv6 multicast |
| `localhost` | Hostname deny |
| `metadata.google.internal` | GCP metadata endpoint |

### Environment variable overrides

| Variable | Effect |
|----------|--------|
| `FORGESCAN_EMERGENCY_DISABLE=true` | Immediately blocks all scanning |
| `FORGESCAN_ALLOWED_CIDRS=10.0.0.0/8,172.16.0.0/12` | Overwrites allowed CIDR list |
| `FORGESCAN_DENIED_CIDRS=10.99.0.0/16` | Overwrites additional denied CIDRs |

### Emergency disable (kill switch)

To immediately stop all scanning without redeploying:

```bash
# Via environment variable (restart required for daemon mode)
export FORGESCAN_EMERGENCY_DISABLE=true

# In Kubernetes — patch the ConfigMap and restart pods
kubectl set env deployment/forgescan-network-scanner \
  FORGESCAN_EMERGENCY_DISABLE=true -n forgescan-scanners
kubectl rollout restart deployment/forgescan-network-scanner -n forgescan-scanners
```

When the kill switch is active, the scanner refuses to start and logs an error message. All in-flight scan tasks will complete (they validated targets at task start), but no new tasks will be accepted.

## Kubernetes deployment guidance

### Network scanner placement

The network scanner requires privileged capabilities and should be isolated:

```yaml
securityContext:
  runAsUser: 0              # Required for raw socket access
  capabilities:
    add: [NET_ADMIN, NET_RAW]
    drop: [ALL]              # Drop everything else
  readOnlyRootFilesystem: true
```

**Best practices:**

1. **Dedicated namespace:** Run scanners in `forgescan-scanners`, separate from the API namespace.
2. **Node taints:** Taint scanner nodes with `forgescan/scanner=true:NoSchedule` and add matching tolerations. This prevents non-scanner workloads from running on scanner nodes.
3. **Pod anti-affinity:** Spread network scanners across nodes for network path diversity.
4. **NetworkPolicy:** Restrict scanner egress to only the API service and scan target ranges. Block access to the Kubernetes API server and cloud metadata endpoints.
5. **Separate ServiceAccount:** Use a dedicated ServiceAccount with no RBAC bindings. The scanner communicates with the platform API, not the Kubernetes API.
6. **Resource limits:** Set CPU and memory limits to prevent a runaway scan from affecting co-located workloads.

### Web and cloud scanners

These do not need elevated capabilities:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
```

### Network policies

Example egress policy for the network scanner:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scanner-egress
  namespace: forgescan-scanners
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: forgescan-network-scanner
  policyTypes: [Egress]
  egress:
    # Allow communication with the ForgeScan API
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: forgescan
          podSelector:
            matchLabels:
              app.kubernetes.io/name: forgescan-api
      ports:
        - port: 50051
          protocol: TCP
    # Allow DNS
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
    # Allow scanning target networks (customize per deployment)
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
            except:
              - 10.96.0.0/12    # Kubernetes service CIDR
```

## Remaining gaps

The following items are scaffolded but not yet fully enforced:

1. **DNS-resolved IP check:** When a hostname target passes scope validation, the resolved IP is not re-checked against the scope rules before scanning. This will be addressed in a follow-up by adding a post-resolution check in the network scanning path.
2. **Runtime kill switch without restart:** The current kill switch requires a pod restart to take effect. A future enhancement could poll a platform endpoint or watch a ConfigMap for live disable signals.
3. **Per-org scope isolation:** Scope rules are currently global to the scanner instance. Multi-tenant deployments should use separate scanner instances per tenant with tenant-specific scope configs.
