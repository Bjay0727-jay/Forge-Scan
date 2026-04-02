# Release security process

This repository's release pipeline now includes baseline supply-chain controls for both binary and container releases.

## What CI/CD now does

- **Rust binary SBOMs:** `release-binaries.yml` generates SPDX JSON SBOMs per target binary and publishes them as release assets.
- **Container SBOM + provenance:** `build-docker.yml` enables BuildKit SBOM and provenance generation (`sbom: true`, `provenance: mode=max`).
- **Container signing (keyless):** Docker images are signed via Sigstore keyless signing (`cosign sign`) using GitHub OIDC identity.
- **Release artifact signing (key-based scaffold):** If `COSIGN_PRIVATE_KEY` is configured, release archives/SBOMs are signed with `cosign sign-blob` and uploaded as `.sig` files.
- **Provenance attestations:**
  - Container image provenance is pushed to the registry via `actions/attest-build-provenance`.
  - Release asset provenance is generated for archives, SBOMs, and checksums.
- **Security scanning:**
  - SAST via Semgrep in CI (SARIF advisory reporting).
  - IaC/workflow misconfiguration scanning via Trivy config mode (HIGH/CRITICAL fail gate).
  - Container vulnerability scanning via Trivy image mode (HIGH/CRITICAL fail gate).

## Required repository configuration and secrets

### Required permissions

GitHub Actions workflows rely on:

- `id-token: write` for Sigstore keyless signing and attestations.
- `attestations: write` for provenance generation.
- `packages: write` for GHCR image publishing.
- `security-events: write` to upload SARIF scan results.

### Optional secrets for artifact signing

Set these repository secrets to enable signed binary release assets:

- `COSIGN_PRIVATE_KEY` — Cosign private key in PEM format.
- `COSIGN_PASSWORD` — Password for the Cosign private key (if encrypted).

If these are not configured, binary archives are still released, but `.sig` files are not generated.

## Additional CI controls

- **Dependency review:** `ci.yml` runs `actions/dependency-review-action` on every pull request, blocking merges that introduce dependencies with HIGH+ vulnerabilities or copyleft licenses (GPL, AGPL, SSPL).
- **License and advisory compliance (cargo-deny):** `ci.yml` runs `cargo-deny` against `engine/deny.toml` to enforce license allowlists, deny known-bad licenses, flag yanked or unmaintained crates, and warn on duplicate dependencies.
- **Agent image pipeline:** `build-docker.yml` now builds both `forgescan-scanner` and `forgescan-agent` images with the same signing, SBOM, Trivy scanning, and provenance attestation controls.

## Operational follow-up

1. Enforce branch protection requiring CI checks, including SAST/IaC scan, cargo-deny, and dependency-review jobs.
2. Verify GHCR consumers pull by digest and optionally verify Sigstore signatures.
3. Publish an internal verification playbook for:
   - `cosign verify` on container images (both scanner and agent).
   - `cosign verify-blob` on binary artifacts.
   - Attestation verification for provenance claims.
4. Review `engine/deny.toml` license allowlist when adding new dependencies.
