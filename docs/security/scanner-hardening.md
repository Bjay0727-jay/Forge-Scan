# Scanner hardening foundation

## Minimum Linux capabilities

Use the smallest capability set needed for active network scans:

- `NET_RAW`: required for raw packet crafting/capture and SYN probing.
- `NET_ADMIN`: only required when scan modes need low-level interface/socket tuning.

For non-network scanner roles (web/cloud), drop all capabilities.

## Guardrails added

Scanner runtime now supports execution guardrails from config:

- `scanner.kill_switch`: emergency global stop for scan task execution.
- `scanner.allowed_cidrs`: optional allow-list CIDRs. If set, IP targets must be in at least one CIDR.
- `scanner.denied_targets`: explicit deny-list (exact host/IP/CIDR match).
- `scanner.max_targets_per_task`: hard cap on target count per task.
- `scanner.max_concurrent_scans`: existing concurrency limiter remains enforced.

Guardrails are fail-closed for violations and emit warning logs with blocked target context.

## Kubernetes safer placement guidance

- Network scanner deployment keeps only `NET_RAW` + `NET_ADMIN` and sets:
  - `allowPrivilegeEscalation: false`
  - `runAsNonRoot: false` (scanner still needs root for raw sockets)
  - `seccompProfile: RuntimeDefault`
- Web/cloud scanner deployments run non-root and drop all Linux capabilities.
- Use node isolation (taints/tolerations + node selectors) for privileged scanner placement.
