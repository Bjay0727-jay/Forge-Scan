# Configuration management

This document describes how environment configuration and secrets are managed for the ForgeScan Cloudflare Workers API.

## Environment separation

The `wrangler.jsonc` file uses Wrangler's named environments to separate dev, staging, and production configuration:

| Command | Environment | Behavior |
|---------|------------|----------|
| `wrangler dev` | development | Uses top-level vars (safe local defaults) |
| `wrangler deploy --env staging` | staging | Uses `env.staging` vars |
| `wrangler deploy --env production` | production | Uses `env.production` vars + production routes |

**Design principle:** Top-level configuration defaults to development-safe values. Running `wrangler dev` without flags uses localhost CORS origins and `ENVIRONMENT=development`. Production values are only applied when explicitly deploying with `--env production`.

## What is committed (and why)

The following values are committed in `wrangler.jsonc` and are **not secrets**:

- **D1 `database_id`** and **KV `id`**: Cloudflare resource identifiers that reference which database/namespace to bind. They are not access credentials.
- **R2 `bucket_name`**: The bucket name is a resource identifier.
- **`ENVIRONMENT`**, **`API_VERSION`**, **`CORS_ORIGIN`**: Non-sensitive runtime configuration that varies per environment.
- **Routes and zone names**: Public DNS routing configuration.

## Secrets (must not be committed)

The following values must be set per-environment using `wrangler secret put`:

| Secret | Required | Description |
|--------|----------|-------------|
| `JWT_SECRET` | Yes | HMAC-SHA256 key for signing JWT tokens. Must be unique per environment. |
| `NVD_API_KEY` | No | NIST NVD API key for higher rate limits on vulnerability data sync. |
| `SENDGRID_API_KEY` | No | Email notification service key. |
| `ANTHROPIC_API_KEY` | No | AI-assisted analysis features. |

### Setting secrets

```bash
# Production
wrangler secret put JWT_SECRET --env production
wrangler secret put NVD_API_KEY --env production

# Staging
wrangler secret put JWT_SECRET --env staging
```

Secrets are stored encrypted by Cloudflare and injected at runtime as `c.env.<SECRET_NAME>`.

## Operator setup checklist

### New environment setup

1. Create a D1 database: `wrangler d1 create forgescan-db-<env>`
2. Create a KV namespace: `wrangler kv namespace create CACHE --env <env>`
3. Create an R2 bucket: `wrangler r2 bucket create forgescan-storage-<env>`
4. Update `wrangler.jsonc` with the new resource IDs in the environment block
5. Run D1 migrations: `wrangler d1 migrations apply forgescan-db-<env> --env <env>`
6. Set required secrets: `wrangler secret put JWT_SECRET --env <env>`
7. Deploy: `wrangler deploy --env <env>`

### Production deployment

```bash
# Apply any pending database migrations first
wrangler d1 migrations apply forgescan-db --env production

# Deploy the worker
wrangler deploy --env production
```

## Scanner engine configuration

The Rust scanner engine uses a separate TOML-based configuration system. See `engine/config/scanner.example.toml` for the full reference. Scanner secrets (API keys, TLS certificates) are injected via environment variables with the `FORGESCAN_` prefix or mounted as files in Kubernetes.
