# new-api Zpika Degradation Monitor

An independent degradation-monitoring service for new-api deployments. It schedules Pelican and optional Candy checks through the Manxue API, keeps recent results, exposes a compact public view, and provides an authenticated administrator console.

## Features

- Standard five-field cron schedules in the Asia/Shanghai time zone
- Per-target model selection with discovery through the configured upstream API key
- Up to three attempts for failed checks
- Encrypted storage for upstream URLs, API keys, and Bark endpoints
- Public result cards and a 60-entry combined status history
- Administrator-only failure details and Bark test notifications
- Explicit CSP allowlist for embedding the public page and result artifacts
- Optional account quarantine through sub2api, with a single group recheck and team account counts in the final Bark alert

## Container image

GitHub Actions builds `linux/amd64` and `linux/arm64` images on every push to `main`:

```text
ghcr.io/spacex-3/new-api-zpika-degradation-monitor:latest
```

The Docker build runs the Go test suite before producing the runtime image.

## Configuration

Copy `compose.example.yml` to `compose.yml`, then set deployment-specific values in a local `.env`. Never commit `.env`, `data/`, `secrets/`, backups, API keys, Bark device keys, or generated result artifacts.

| Variable | Purpose | Default |
| --- | --- | --- |
| `ALLOWED_HOST` | Accepted HTTP host name | `localhost` |
| `PUBLIC_ORIGIN` | Exact administrator origin used for CSRF checks | `http://localhost:8080` |
| `MANXUE_BASE_URL` | Detection API origin | `https://manxue.ai` |
| `TRUST_CLOUDFLARE` | Trust Cloudflare client-IP headers | `false` |
| `EMBED_PARENT_ORIGINS` | Comma-separated HTTPS origins allowed to embed `/embed` | empty |

The service reads secrets from files mounted by Compose:

- `encryption-key`: a base64-encoded 32-byte key used for AES-GCM encryption
- `session-key`: a base64-encoded value containing at least 32 bytes
- `admin-token-hash`: the hexadecimal SHA-256 digest of the administrator token
- `bootstrap-base-url`: an optional initial new-api-compatible Base URL

Create these files locally with restrictive permissions. Keep the original encryption key with the data directory; changing it makes stored credentials unreadable.

## Automatic account quarantine

The administrator console can store separate HTTPS root URLs and administrator credentials for new-api and sub2api. All connection details are AES-GCM encrypted at rest and never returned to the browser. Saving this configuration requires the monitor administrator token again, in addition to the session and CSRF checks. Empty connection fields retain saved values. The feature is disabled until explicitly enabled.

Only degraded, suspicious or incorrect results for `codex-满血不降智` and `codex-不降智` are eligible. Give each target a dedicated new-api key and configure its exact token name (defaults: `鹈鹕-满血` and `鹈鹕-不降智`). The monitor requires a unique successful new-api log matching group, token name, model, completion time (within 30 seconds) and input/output tokens. The actual channel must be both ID `23` and name `sub2api_pro`.

Next, it requires one matching sub2api usage record in the OpenAI `team` group, using model, completion time and tokens including cached input. Both source `team` and destination `降智` groups must resolve uniquely. Incomplete, overlapping or excessive log pagination stops the operation. Missing or ambiguous matches never trigger account writes.

The account must still belong to team and must not already belong to 降智. Only its group memberships are updated: unrelated memberships are preserved. A persisted intent precedes the write, and a fresh read verifies the complete resulting membership set. A failed write is never retried automatically; if verification is uncertain, that account is blocked from further automatic migration until an administrator investigates. The audit survives restarts. Do not run multiple monitor instances against the same state directory. Sub2api's update API has no conditional-write transaction with manual administrator changes, so avoid editing the same account's memberships during automatic handling.

After a confirmed migration, the target runs one recheck (with the existing maximum three request attempts), without changing its cron schedule or recursively quarantining more accounts. The original alert is followed by one final processing alert, including skipped/failed outcomes. A normal recheck means that the **group** passed; routing may have selected another channel. Completed history is bounded to 100 events; unresolved migrations are retained for manual review. Only administrators can read these audit events.

Final Bark messages include current team counts: available, rate limited and total. Error, disabled, expired, overloaded or temporarily unschedulable accounts are counted as other unavailable when applicable. A statistics API failure is reported explicitly instead of showing zero. “Test management connection and team statistics” uses saved settings and only reads management data; it does not migrate accounts or start paid detections.

Security references used for this integration: OWASP ASVS **5.0.0** (3.5.1 CSRF, 11.3.3 authenticated encryption, 12.3.1–12.3.2 encrypted service connections and certificate validation, 16.2.5 credential-free audit data), Authentication Cheat Sheet and Session Management Cheat Sheet. External credentials stay server-side; redirects are rejected. This is a focused control review, not a full application ASVS certification.

## Scheduled sub2api status reports

The administrator console provides a separate report switch, five-field cron expression, low-account thresholds, next scheduled time and last delivery result. The default cron is `0 8-22/2 * * *` in Asia/Shanghai: daily at 08:00, 10:00, 12:00, 14:00, 16:00, 18:00, 20:00 and 22:00. Enable reporting after saving the existing sub2api credentials and Bark endpoint. Automatic quarantine can remain disabled independently.

Each report reads the OpenAI groups named exactly `team`, `降智` and `free`, and sends one Bark with available, rate-limited and total account counts. Other unavailable accounts are shown separately. By default, team available **below 5** or 降智 available **below 1** produces a prominent title and a warning before the counts. Thresholds are editable; 0 disables that group's low-account warning. Free has no low-account threshold. Missing/ambiguous groups or failed reads are reported as unknown, never zero, while other groups are still included.

“Send status notification now” uses the saved thresholds and does not change the recurring schedule, migrate accounts, or run paid checks. Scheduled slots are persisted before delivery to prevent duplicates after restarts. Missed slots older than one minute are skipped, so restarting at night does not replay daytime reports. An uncertain Bark response is not automatically retried; inspect the last delivery result and use the manual button if needed. Reports use the existing Bark endpoint independently of the detection result notification scope.

## Development

```bash
go test ./...
docker build -t degradation-monitor:dev .
```

Production hosts should pull the image built by GitHub Actions. They do not need the Go toolchain or a local image build.
