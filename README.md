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

## Development

```bash
go test ./...
docker build -t degradation-monitor:dev .
```

Production hosts should pull the image built by GitHub Actions. They do not need the Go toolchain or a local image build.
