# ForgeScan Deployment Guide

This directory contains deployment configurations for ForgeScan.

## Directory Structure

```
deploy/
├── kubernetes/          # Raw Kubernetes manifests (Kustomize)
│   ├── base/           # Base manifests
│   └── overlays/       # Environment-specific overlays
│       ├── dev/
│       └── prod/
└── helm/               # Helm chart
    └── forgescan/
```

## Quick Start

### Prerequisites

- Kubernetes 1.25+
- Helm 3.x (for Helm deployment)
- kubectl configured with cluster access
- (Optional) NGINX Ingress Controller
- (Optional) cert-manager for TLS certificates

### Option 1: Helm Deployment (Recommended)

```bash
# Add dependencies
helm repo add bitnami https://charts.bitnami.com/bitnami
helm dependency update ./helm/forgescan

# Install with default values
helm install forgescan ./helm/forgescan \
  --namespace forgescan \
  --create-namespace

# Install with custom values
helm install forgescan ./helm/forgescan \
  --namespace forgescan \
  --create-namespace \
  -f my-values.yaml
```

### Option 2: Kustomize Deployment

```bash
# Deploy base configuration
kubectl apply -k kubernetes/base

# Deploy with dev overlay
kubectl apply -k kubernetes/overlays/dev

# Deploy with prod overlay
kubectl apply -k kubernetes/overlays/prod
```

## Configuration

### Minimum Production Configuration

Create a `values-prod.yaml`:

```yaml
api:
  replicaCount: 3
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 2000m
      memory: 2Gi

networkScanner:
  replicaCount: 5
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 20

ingress:
  enabled: true
  hosts:
    - host: forgescan.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
          service: api
  tls:
    - secretName: forgescan-tls
      hosts:
        - forgescan.yourdomain.com

postgresql:
  enabled: true
  auth:
    password: "YOUR_SECURE_PASSWORD"
  primary:
    persistence:
      size: 100Gi

nvd:
  apiKey: "YOUR_NVD_API_KEY"

ingestion:
  tenable:
    enabled: true
    accessKey: "YOUR_TENABLE_ACCESS_KEY"
    secretKey: "YOUR_TENABLE_SECRET_KEY"
```

### AWS EKS with IRSA

For AWS EKS, configure IAM Roles for Service Accounts:

```yaml
cloudScanner:
  enabled: true
  aws:
    useIRSA: true
    roleArn: "arn:aws:iam::ACCOUNT_ID:role/forgescan-cloud-scanner"
    region: "us-east-1"
```

### External Database

To use an external PostgreSQL database:

```yaml
postgresql:
  enabled: false
  external:
    host: "your-postgres-host.rds.amazonaws.com"
    port: 5432
    database: forgescan
    username: forgescan
    password: "YOUR_PASSWORD"
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    KUBERNETES CLUSTER                        │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              forgescan namespace                     │    │
│  │  ┌──────────────┐  ┌──────────────┐                 │    │
│  │  │ forgescan-   │  │ forgescan-   │                 │    │
│  │  │ api (2-10)   │  │ dashboard    │                 │    │
│  │  └──────────────┘  └──────────────┘                 │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           forgescan-scanners namespace               │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐   │    │
│  │  │ network-     │  │ webapp-      │  │ cloud-   │   │    │
│  │  │ scanner(2-20)│  │ scanner(2)   │  │ scanner  │   │    │
│  │  └──────────────┘  └──────────────┘  └──────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            forgescan-data namespace                  │    │
│  │  ┌──────────────┐  ┌──────────────┐                 │    │
│  │  │ PostgreSQL   │  │ Redis        │                 │    │
│  │  └──────────────┘  └──────────────┘                 │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Scanner Node Requirements

The network scanner requires elevated privileges for raw socket access:

```yaml
securityContext:
  runAsUser: 0
  capabilities:
    add:
      - NET_ADMIN
      - NET_RAW
```

For dedicated scanner nodes, use taints and tolerations:

```bash
# Taint nodes for scanner workloads
kubectl taint nodes scanner-node-1 forgescan/scanner=true:NoSchedule

# Scanners will automatically tolerate this taint
```

## Monitoring

Enable Prometheus metrics:

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 30s
```

## Upgrading

```bash
# Helm upgrade
helm upgrade forgescan ./helm/forgescan \
  --namespace forgescan \
  -f values-prod.yaml

# Kustomize upgrade
kubectl apply -k kubernetes/overlays/prod
```

## Troubleshooting

### Check pod status
```bash
kubectl get pods -n forgescan
kubectl get pods -n forgescan-scanners
kubectl get pods -n forgescan-data
```

### View logs
```bash
kubectl logs -f deployment/forgescan-api -n forgescan
kubectl logs -f deployment/forgescan-network-scanner -n forgescan-scanners
```

### Database connection
```bash
kubectl exec -it postgres-0 -n forgescan-data -- psql -U forgescan
```

## Security Considerations

1. **Secrets Management**: Use external secrets (Vault, AWS Secrets Manager, etc.) in production
2. **Network Policies**: Enabled by default to restrict pod-to-pod communication
3. **TLS**: Use cert-manager for automatic certificate management
4. **RBAC**: Service accounts with minimal required permissions
5. **Pod Security**: Non-root containers where possible (except network scanner)

## License

Proprietary - Forge Cyber Defense
