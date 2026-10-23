# SearXNG image trust correction

SearXNG has independent system and Python certificate stores. Updating Odysseus's Python environment does not update this sidecar. The pinned SearXNG image includes certificate authorities listed in the public eMudhra incident inventory. `docker/searxng/Dockerfile` derives a corrected image from the same immutable application base, without downloading dependencies or changing the SearXNG version.

The build removes the 21 known incident CA certificates by SHA-256 fingerprint from system CA source files and certifi, regenerates the system PEM bundle and hashed CA directory, and checks the generated stores. Only certificates present in the base are removed: the inspected amd64 image loses two system roots and one certifi root. Unaffected certificates remain. The image's existing certifi package version metadata is unchanged; this is an image-owned trust-content correction rather than a package upgrade.

The runtime is Void Linux with its package manager removed. Do not substitute Alpine, Debian or XBPS package-install commands. Removing affected source certificates is necessary because the upstream root entrypoint runs `update-ca-certificates` again at startup.

## Build and validate

Run these commands from the repository root on a Docker host. The build context allowlist excludes credentials and unrelated application files. The repair requires no build-step network; pulling the pinned base still needs registry access.

```sh
# Reproduce the affected upstream behavior with offline public chain fixtures.
docker build --network=none --target baseline-validation -f docker/searxng/Dockerfile .

# Check corrected trust and actual upstream entrypoint/loopback health.
docker build --network=none --target validation -f docker/searxng/Dockerfile .

# Also exercise verified HTTPS through SearXNG's own curl client and a real search.
# Requires outbound networking and working upstream engines.
docker build --target live-validation -f docker/searxng/Dockerfile .

# Build the runtime image and select it through the opt-in Compose overlay.
docker compose -f docker-compose.yml -f docker/searxng/compose.yml build searxng
docker compose -f docker-compose.yml -f docker/searxng/compose.yml up -d --no-deps searxng
docker compose -f docker-compose.yml -f docker/searxng/compose.yml ps searxng
```

The overlay retains the base service's settings migration, persistent configuration, healthcheck, ports and capability limits. All Compose commands managing this local image must include the overlay; using only the base file selects its original image. Validation fixtures and validation scripts are excluded from the runtime stage.

The offline checks use fourteen public incident chains, including two without Certificate Transparency entries, with a frozen verification time, hostname verification and affected positive controls. They independently exercise the system PEM, system hashed directory and certifi bundle. The unpatched baseline must accept 14/14, 14/14 and 7/14 respectively; the corrected image must reject all fourteen in every store. The startup check rechecks system trust after the upstream entrypoint regenerates it. Live validation requires an ordinary verified HTTPS request, certificate-verification failures for all fourteen incident hosts through SearXNG's own curl client after startup, and nonempty SearXNG JSON search results; network and engine availability can cause that optional target to fail.

## Scope and rollout

The `ci / SearXNG image` workflow builds on native amd64 and arm64 runners. Each architecture reproduces the affected upstream stores, checks the repaired image with build-step networking disabled, then starts the actual runtime through the base Compose service's settings wrapper, capabilities and healthcheck. The CI override removes published ports and uses a fresh temporary configuration volume; it does not replace the service's startup path. Live checks run against that existing service without repairing its trust stores. Pull requests perform these checks without registry credentials or publication.

On the canonical repository's `dev`, `main` or initial `release/searxng-ca-trust` branch, successful native checks allow a separate job to publish the exact exported images to `ghcr.io/odysseus-dev/odysseus-searxng`. Explicit workflow runs on those branches can also request publication. The publisher verifies source revisions, source-input checksums and architecture digests before recording the immutable multiarch reference. Tags identify the commit and workflow attempt; no moving `latest` or `dev` tag is changed. Fresh native jobs then pull anonymously and repeat Compose/live validation. Only after both pass does the workflow produce the `searxng-release` artifact with `searxng-release.json` for the coordinated Compose pin update.

For the first publication, a repository administrator must make the new GHCR package public before anonymous verification can succeed. Rerun the failed verification jobs after changing package visibility. The initial release branch permits this bootstrap before the workflow reaches the default branch; it does not merge or deploy the application. Future publication can use the normal trusted-branch push or explicit workflow trigger.

Validate each target architecture on a native builder or an explicitly configured emulation builder. An amd64 success does not establish arm64 support. This patch preserves the upstream default identity and entrypoint; it does not alter host trust, existing running containers or operator-mounted/custom trust stores. Operators must inspect those overrides separately. Removing AAA Certificate Services can also affect unrelated legacy certificate chains anchored solely there; test configured engines and any private integrations before rollout.

After architecture validation and independent review, publish an approved multi-architecture runtime image, record its immutable digest, and update the base and standalone GPU Compose pins together. The opt-in overlay permits local validation before a published reference exists. Recreate affected services after selecting the replacement. Keep the broader incident remediation tracker open for deployment and other runtime work.

## Public fixture provenance

Fingerprint inventory: <https://emudhra.we-have-a-problem.com/roots.json> and <https://emudhra.we-have-a-problem.com/impacted-intermediates.json>. The cross-signed issuer and chain fixtures come from <https://emudhra.we-have-a-problem.com/chains.zip> (archive SHA-256 `7b949956955fc501a30f4d98d2f513d34c0bbbe92e29a968194c96e097ce2345`). Fixtures contain public certificates only. Each fixture certificate's fingerprint is verified before chain checks.

The same incident follow-up updates Odysseus's application bootstrap and independent bundled clients; see [outbound TLS trust](tls-trust.md). Those package updates do not change the derived SearXNG application/package versions. The base-image alignment regression requires its immutable upstream base to match the deployment pins until a verified derived release is selected, with the local overlay tag matching the application date.
