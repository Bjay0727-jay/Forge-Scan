# Cloudflare runtime configuration hygiene

## Risks identified

- Production-specific runtime values were previously mixed into the default Wrangler config, increasing accidental prod deploy risk.
- Environment resource bindings (D1/KV) were not clearly separated for dev/staging/prod workflows.
- Secrets should never be committed into `wrangler.jsonc`; they must be injected via `wrangler secret put` or CI secrets.

## What changed

- `cloudflare/forgescan-api/wrangler.jsonc` now uses **development-safe defaults** at the top level.
- Added explicit `env.dev`, `env.staging`, and `env.production` sections with separate bindings and variables.
- Added placeholders for non-production resource IDs to prevent accidental reuse of production infrastructure.

## Operator workflow

1. Create environment-specific resources in Cloudflare (D1, KV, R2).
2. Replace placeholder IDs in `env.dev` and `env.staging`.
3. Keep production IDs only in `env.production`.
4. Inject secrets (never commit them):
   - `npx wrangler secret put JWT_SECRET --env dev`
   - `npx wrangler secret put JWT_SECRET --env staging`
   - `npx wrangler secret put JWT_SECRET --env production`
5. Deploy explicitly by environment:
   - `npx wrangler deploy --env dev`
   - `npx wrangler deploy --env staging`
   - `npx wrangler deploy --env production`

## Values that remain committed (and why)

- Cloudflare resource IDs (D1/KV) and bucket names remain in repo config because Wrangler needs binding metadata to compile/deploy.
- These IDs are not credentials, but they are still environment-sensitive and should be scoped per environment.
