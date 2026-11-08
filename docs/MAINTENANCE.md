# Maintainer notes

## Testing and live workflows

Start with the README's CLI help and regression tests. The unit-test workflow runs on pull requests and pushes to the default branch with read-only repository access. Its test process blocks outbound connections and subprocess launches. A passing test run covers the regression suite only.

The existing live scan jobs are gated by the repository variable `ENABLE_LIVE_SCANS`. Set it to `true` only after reviewing the targets, scope, dependencies, runner access and notification destinations. Their historical schedules remain defined. Raw reports are no longer uploaded as workflow artifacts. Treat older run logs and artifacts as separate copies when cleaning up data.

## Credentials and reports

Use local environment variables or ignored `.env` files. The standalone CORS helper takes `H1_AUTHORIZED_BASE_URL` and an optional `H1_SCAN_COOKIE`. API-key verification requires an operator-supplied key. Use synthetic data in tests and public bug reports. Generated proof scripts are review-only text files. Inspect them in an isolated environment before any manual execution. Tool discovery writes a list for review.

Treat any previously committed session or private key as exposed. Invalidate affected sessions or rotate credentials you control. For third-party material, use the owner's private disclosure channel. Review old branches, pull requests, artifacts, caches and clones separately. Removing a file from the current branch does not remove its historical copies.

## Optional local services

For Compose, set deployment-specific `NEO4J_PASSWORD` and `FREELLMAPI_ENCRYPTION_KEY` in your local environment. Rotate existing database credentials inside Neo4j if an earlier deployment used the old default. For the optional configuration portal, also set `H1_CONFIG_TOKEN`, enable the `config` Compose profile, and sign in on localhost as `operator` using that token. Updating a field preserves other settings. The Telegram bot requires both `TELEGRAM_CHAT_ID` and `TELEGRAM_USER_ID` to accept commands.

## Releases

Before tagging a release, run the suite on the intended revision, verify install and CLI help from a fresh checkout, and review all files in the proposed distribution. Check the [third-party inventory](../THIRD_PARTY.md), including binaries, rules and datasets, before distributing an archive. No packaged release is claimed here.
