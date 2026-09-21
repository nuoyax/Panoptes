# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | ✅        |
| 1.0.x   | ✅        |

## Reporting a Vulnerability

Please open a private security advisory on GitHub, or contact the maintainer directly. Do not open public issues for security vulnerabilities.

## Scope

- This service only reads public CT log data; it stores nothing sensitive.
- The SQLite database (`data/`) contains only public subdomain names and enrichment results, and is gitignored.
- No authentication/credentials are required or stored.

## Active connections to third-party hosts — read before deploying

Panoptes is not purely passive. The subdomain lookup only queries public CT
sources, but the **enrichment stages — `dns`, `http`, `ports` and `security` —
connect to the resolved hosts of the apex you query**:

| Stage | What leaves your machine |
|---|---|
| `dns` | An A-record lookup for every subdomain found |
| `http` | An HTTP request to each DNS-alive host (status code and page title) |
| `ports` | A TCP connect attempt against 38 common ports on each DNS-alive host |
| `security` | Requests to 22 well-known sensitive paths (`/.git/HEAD`, `/.env`, `/admin/`, …), plus security-header inspection and a TLS handshake |

These are baseline, non-exploitative checks — nothing is fetched beyond a
status code and nothing is modified — but they are **outbound requests to
infrastructure you may not own**. The sensitive-path probe in particular will
appear in a third party's access log as an attempt to read `/.env` or
`/.git/HEAD`.

Before pointing this at a domain:

- Only scan domains you own or have **written authorization** to test. A
  self-hosted deployment does not grant that authorization — you are the
  operator, and the decision is yours to document.
- Bound the blast radius with `JOB_MAX_CONCURRENT`, `MAX_SCAN_HOSTS`,
  `MAX_HTTP_HOSTS` and `HTTP_PROBE_TIMEOUT` in `backend/config.py`.
- Keep `HTTP_VERIFY_TLS` at its default (`False`) only for scanning targets
  with self-signed certificates; set it to `True` if you would rather the
  probe fail than connect to an unverified host.
- The API has **no authentication**. Bind it to `127.0.0.1` (or behind an
  authenticating reverse proxy) so it is not an open scanning relay for anyone
  who can reach the port. `POST /api/v1/scan` in particular lets a caller
  direct traffic at an arbitrary apex — that is the intended feature and the
  reason it should not be public.
- `DELETE /api/v1/jobs/{id}` cancels a running scan, but it is a soft cancel:
  already-finished stages stay persisted.
