# Rust NMS

This application foundation provides an Axum bootstrap, PostgreSQL integration and migrations, JWT/RBAC login, health checks, device inventory CRUD, and ICMP-based CIDR discovery with an allowlist and concurrency limits. The periodic polling worker checks ICMP, per-device configured TCP ports, the legacy SSH port when SSH credentials are available, and SNMP v2c/v3 when configured. Device status, metrics, alert transitions, and a transactional outbox are stored in PostgreSQL/TimescaleDB. Device status and alert transitions are available through an authenticated WebSocket.

## Requirements

- Rust 1.94 or later
- PostgreSQL 17 with TimescaleDB 2.x installed and the `timescaledb` extension available
- `DATABASE_URL` to validate SQLx queries at compile time, or offline `.sqlx` metadata generated with `cargo sqlx prepare`

## Quick install (Ubuntu)

On Ubuntu 22.04 or 24.04, run this from an interactive terminal after the installer is available on `main`:

```sh
curl -fsSL https://raw.githubusercontent.com/elsm4n/NMS-light/main/scripts/install-ubuntu.sh | bash
```

The installer asks for the initial admin email and password, requests `sudo` when needed, installs PostgreSQL 17 and TimescaleDB, builds the app against a temporary migrated database for SQLx checks, then installs and starts a `systemd` service. The API listens only on `127.0.0.1:8080`; discovery stays disabled. It refuses to overwrite an existing app installation or PostgreSQL 17 cluster. This is a development/single-server setup, not a substitute for production backups, TLS/reverse proxy, or high availability.

## Configuration

Copy `.env.example` to `.env`, then set `NMS_DATABASE_URL`, `NMS_JWT_SECRET` (at least 32 bytes), and `NMS_CREDENTIAL_KEY_HEX` (exactly 32 bytes represented by 64 hexadecimal characters). Do not commit `.env` or use example values as secrets.

On the first startup, when the `users` table is empty, set `NMS_BOOTSTRAP_ADMIN_EMAIL` and `NMS_BOOTSTRAP_ADMIN_PASSWORD` (at least 16 characters). The admin account is created only if no users exist; the bootstrap variables can be removed afterward. The application runs embedded migrations at startup, including creation of the TimescaleDB hypertable.

Discovery is disabled by default. To enable it, set `NMS_DISCOVERY_CIDRS` to a comma-separated list of CIDRs covering only networks you manage. `NMS_MAX_PROBE_CONCURRENCY` sets the global concurrency limit for polling and discovery probes (1–512; default 32). The scheduler checks active devices every second and starts only devices whose `poll_interval_seconds` has elapsed; probes for each device run serially so the global limit remains accurate. On shutdown, the scheduler stops starting new work and waits for active probes, bounded by each device's timeout.

## Build and run

```sh
DATABASE_URL="$NMS_DATABASE_URL" cargo check
DATABASE_URL="$NMS_DATABASE_URL" cargo test
DATABASE_URL="$NMS_DATABASE_URL" cargo run
```

The listener binds to `127.0.0.1:8080` by default; set `NMS_LISTEN_ADDR` if deployment requires a different bind address. The readiness endpoint fails if the database is unreachable.

## Current endpoints

- `GET /health/live` — process liveness.
- `GET /health/ready` — database connectivity readiness.
- `POST /api/v1/auth/login` — JSON login `{ "email": "...", "password": "..." }`; returns an HS256 JWT valid for 15 minutes.
- `POST /api/v1/auth/ws-ticket` — exchanges a valid JWT for a one-time WebSocket ticket valid for 30 seconds.
- `POST /api/v1/discovery/scans` — scans a CIDR entirely within the allowlist, for example `{ "cidr": "192.168.1.0/24" }`; admin/operator only, with a maximum of 1,024 addresses per request. Hosts that respond to ICMP are added as new devices of type `other`; existing inventory is not overwritten.
- `GET /api/v1/devices?page=1&per_page=50` — paginated device list.
- `GET /api/v1/devices/{id}` — device details without returning ciphertext or secrets.
- `POST /api/v1/devices` — create a device. The optional `tcp_probe_ports` field accepts up to 32 unique ports (1–65535), for example `[22, 80, 443]`.
- `PUT /api/v1/devices/{id}` — replace the full device representation; omitted credentials are removed. For `tcp_probe_ports` specifically, omitting the field preserves the existing list; send `[]` to remove all additional TCP ports.
- `DELETE /api/v1/devices/{id}` — soft-delete a device, disabling it without deleting its history.
- `GET /api/v1/alerts/rules`, `POST /api/v1/alerts/rules`, and `PUT /api/v1/alerts/rules/{id}` — read, create, or replace a rule and its `endpoint_ids`. `PATCH /api/v1/alerts/rules/{id}/enabled` accepts `{ "is_enabled": false }` to disable rule evaluation. Supported metrics: `icmp_reachable`, `icmp_latency_ms`, `tcp_reachable`, `tcp_connect_latency_ms`, `snmp_reachable`, `sys_uptime_seconds`, `snmp_cpu_percent`, `snmp_memory_used_percent`, `snmp_if_in_bps`, and `snmp_if_out_bps`. The optional `series_key` selects a single TCP/interface series (e.g. `port=443` or `ifIndex=2`); an interface rule is invalid without a selector, while a TCP rule without a selector still matches the legacy series. Rules also accept `comparison`, warning/critical thresholds, consecutive-failure and recovery-success counts, device selectors, and `endpoint_ids`.
- `POST /api/v1/alerts/preflight` — simulates a draft rule against the history of one device/series (up to 7 days and 500 samples), returning transitions, estimated coverage/gaps, and a preview payload for the selected provider endpoint. This operation is read-only: it does not write alerts/outbox rows, send HTTP requests, or publish WebSocket events. Endpoint secrets are omitted or redacted. See the [alert preflight guide](docs/alert-preflight.md).
- `GET /api/v1/alerts` — latest alert-state snapshot; `GET /api/v1/alerts/events` — transition history.
- `GET /api/v1/webhooks`, `POST /api/v1/webhooks`, and `PUT /api/v1/webhooks/{id}` — read, create, or replace notification configuration. `provider` can be `generic` (default), `telegram`, `slack`, or `discord`: generic uses `url` and an optional `bearer_token`; Telegram uses `bot_token` and `chat_id`; Slack uses an incoming webhook URL like `https://hooks.slack.com/services/...`; Discord uses a URL like `https://discord.com/api/webhooks/{id}/{token}`. `PATCH /api/v1/webhooks/{id}/enabled` accepts `{ "is_enabled": false }`; queued deliveries are held while an endpoint is disabled and resume when it is re-enabled. Connections use HTTPS on port 443, accept only public DNS resolutions, pin the resolved IP addresses, and reject redirects. All provider configuration (including URLs, tokens, and Telegram `chat_id`) is encrypted and never returned by the API. See [provider contracts and official sources](docs/webhook-providers.md).
- `GET /api/v1/ws` — streams `device.status`, `alert.transition`, and `stream.gap` events. For browsers, request a ticket with the bearer JWT, then offer the `cue-events-v1` and `cue-ticket.<ticket>` subprotocols when opening the WebSocket. Tickets are deleted when used. After `stream.gap`, fetch a fresh snapshot through REST.

Send `Authorization: Bearer <token>` on device, alert, and webhook routes. Admins and operators can modify inventory, rules, and endpoints; viewers can only read. SNMP/SSH credential fields are encrypted before being written; responses include only the `has_snmp_credentials` and `has_ssh_credentials` booleans.

## Current-stage notes

Polling records `icmp_reachable` and ICMP latency; `tcp_reachable` and connection latency for each `tcp_probe_ports` entry and the legacy SSH port when SSH credentials are available; `snmp_reachable`; `sys_uptime_seconds`; and, when the agent provides the relevant MIBs, `snmp_cpu_percent` (average `hrProcessorLoad`), `snmp_memory_used_percent` (RAM `hrStorage` rows), `snmp_if_in_bps`, and `snmp_if_out_bps`. `sysName` and `sysDescr` are stored as device metadata. TCP checks only whether the port connection succeeds; the worker does not perform SSH authentication. TCP series use the identity `port=<number>` and interface series use `ifIndex=<index>`; interface names/descriptions are included as metadata when provided by the agent. Interface rates are calculated from IF-MIB counter deltas per interval, preferring 64-bit `ifHC*Octets` counters when available and falling back to 32-bit `if*Octets` counters. The initial sample does not produce a rate; rates are also skipped when a reboot, `ifCounterDiscontinuityTime` change, counter-width change, or unsafe counter decrease is detected. Counters are stored exactly as decimal text to preserve 64-bit values, and the baseline survives restarts. Failures in optional CPU/RAM/interface walks do not change the base SNMP-reachable status. `up` means all configured probes succeeded, `degraded` means some succeeded, and `down` means none succeeded. Alerts evaluate incoming metrics and apply consecutive-failure and recovery-success rules, then store per-series state, events, and outbox rows atomically with the polling transaction. The dispatcher sends provider-specific notifications serially through the outbox, without a proxy or redirects, with timeouts and exponential retries; each message includes an event ID so receivers can deduplicate it. Polling and WebSocket tickets currently support a single service instance; a distributed scheduler is not yet provided.

Notification cooldowns suppress repeat sends while an alert remains open; escalation to critical and recovery are still notified.

SNMPv3 privacy `AES` is recommended. `DES` is available only for legacy interoperability and is vulnerable to brute force; `3DES` is also slower and is not recommended for new deployments. `async-snmp` provides DES/3DES implementations and the Reeder key extension for combinations that require it.

Login and ticket creation do not yet have per-account/IP rate limits; put a rate limiter in front of the reverse proxy before exposing the endpoint to untrusted networks. Migrations must run against PostgreSQL with TimescaleDB installed. Compile-time query checks and unit tests do not replace full integration testing on PostgreSQL 17 + TimescaleDB 2.x. Generic, Telegram, Slack, and Discord payloads are supported; direct sends to provider accounts are not covered by the smoke test.
