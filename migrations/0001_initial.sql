-- PostgreSQL 17 + TimescaleDB 2.x
-- Credential/config ciphertext uses a versioned AES-256-GCM envelope produced by the application.
-- The encryption key is supplied outside the database (secret manager or protected environment).

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_email_ci_uq ON users (lower(email));

CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address INET NOT NULL UNIQUE,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT NOT NULL DEFAULT 'other'
        CHECK (device_type IN ('router', 'switch', 'firewall', 'server', 'other')),
    location TEXT,
    group_name TEXT,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    deleted_at TIMESTAMPTZ,
    poll_interval_seconds INTEGER NOT NULL DEFAULT 30
        CHECK (poll_interval_seconds BETWEEN 5 AND 86400),
    probe_timeout_ms INTEGER NOT NULL DEFAULT 3000
        CHECK (probe_timeout_ms BETWEEN 100 AND 60000),
    last_status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (last_status IN ('unknown', 'up', 'degraded', 'down')),
    last_checked_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),

    snmp_version TEXT CHECK (snmp_version IS NULL OR snmp_version IN ('v2c', 'v3')),
    snmp_port INTEGER NOT NULL DEFAULT 161 CHECK (snmp_port BETWEEN 1 AND 65535),
    snmp_v2c_community_ciphertext BYTEA,
    snmp_v3_username TEXT,
    snmp_v3_auth_protocol TEXT
        CHECK (snmp_v3_auth_protocol IS NULL OR snmp_v3_auth_protocol IN ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')),
    snmp_v3_auth_secret_ciphertext BYTEA,
    snmp_v3_priv_protocol TEXT
        CHECK (snmp_v3_priv_protocol IS NULL OR snmp_v3_priv_protocol IN ('des', '3des', 'aes128', 'aes192', 'aes256')),
    snmp_v3_priv_secret_ciphertext BYTEA,

    ssh_port INTEGER NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
    ssh_username TEXT,
    ssh_private_key_ciphertext BYTEA,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CHECK (deleted_at IS NULL OR is_enabled = FALSE),
    CHECK (snmp_version IS DISTINCT FROM 'v2c' OR snmp_v2c_community_ciphertext IS NOT NULL),
    CHECK (snmp_version IS DISTINCT FROM 'v3' OR snmp_v3_username IS NOT NULL),
    CHECK (snmp_version IS DISTINCT FROM 'v3' OR snmp_v3_auth_protocol IS NULL OR snmp_v3_auth_secret_ciphertext IS NOT NULL),
    CHECK (snmp_version IS DISTINCT FROM 'v3' OR snmp_v3_priv_protocol IS NULL OR snmp_v3_priv_secret_ciphertext IS NOT NULL),
    CHECK (snmp_v3_priv_protocol IS NULL OR snmp_v3_auth_protocol IS NOT NULL)
);

CREATE INDEX devices_enabled_poll_idx
    ON devices (poll_interval_seconds, ip_address)
    WHERE is_enabled = TRUE AND deleted_at IS NULL;

CREATE INDEX devices_group_idx ON devices (group_name) WHERE deleted_at IS NULL;

CREATE TABLE metrics (
    observed_at TIMESTAMPTZ NOT NULL,
    device_id UUID NOT NULL REFERENCES devices(id),
    metric_name TEXT NOT NULL,
    -- Canonical, deterministic identity for a series (e.g. "ifIndex=2"); scalar metrics use ''.
    series_key TEXT NOT NULL DEFAULT '',
    value DOUBLE PRECISION NOT NULL,
    unit TEXT,
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (observed_at, device_id, metric_name, series_key)
);

SELECT create_hypertable('metrics', 'observed_at', if_not_exists => TRUE);

CREATE INDEX metrics_device_series_time_idx
    ON metrics (device_id, metric_name, series_key, observed_at DESC);
CREATE INDEX metrics_name_time_idx ON metrics (metric_name, observed_at DESC);

CREATE TABLE alert_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    comparison TEXT NOT NULL CHECK (comparison IN ('gt', 'gte', 'lt', 'lte', 'unreachable')),
    warning_threshold DOUBLE PRECISION,
    critical_threshold DOUBLE PRECISION,
    consecutive_failures INTEGER NOT NULL DEFAULT 1 CHECK (consecutive_failures BETWEEN 1 AND 1000),
    recovery_successes INTEGER NOT NULL DEFAULT 2 CHECK (recovery_successes BETWEEN 1 AND 1000),
    cooldown_seconds INTEGER NOT NULL DEFAULT 300 CHECK (cooldown_seconds BETWEEN 0 AND 604800),
    -- Validated by the application against a fixed selector schema; never interpreted as SQL.
    device_selector JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (comparison = 'unreachable' AND warning_threshold IS NULL AND critical_threshold IS NULL)
        OR (comparison <> 'unreachable' AND critical_threshold IS NOT NULL)
    ),
    CHECK (
        warning_threshold IS NULL
        OR (comparison IN ('gt', 'gte') AND critical_threshold >= warning_threshold)
        OR (comparison IN ('lt', 'lte') AND critical_threshold <= warning_threshold)
    )
);

CREATE INDEX alert_rules_enabled_idx ON alert_rules (metric_name) WHERE is_enabled = TRUE;

-- One current state row per rule/device; alert_events preserves every transition.
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID NOT NULL REFERENCES alert_rules(id),
    device_id UUID NOT NULL REFERENCES devices(id),
    state TEXT NOT NULL DEFAULT 'ok' CHECK (state IN ('ok', 'warning', 'critical', 'resolved')),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    consecutive_successes INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_successes >= 0),
    current_value DOUBLE PRECISION,
    last_error TEXT,
    last_evaluated_at TIMESTAMPTZ,
    state_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    opened_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    last_notified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (rule_id, device_id)
);

CREATE INDEX alerts_state_updated_idx ON alerts (state, updated_at DESC);
CREATE INDEX alerts_device_updated_idx ON alerts (device_id, updated_at DESC);

CREATE TABLE alert_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID NOT NULL REFERENCES alerts(id),
    from_state TEXT NOT NULL CHECK (from_state IN ('ok', 'warning', 'critical', 'resolved')),
    to_state TEXT NOT NULL CHECK (to_state IN ('warning', 'critical', 'resolved')),
    metric_value DOUBLE PRECISION,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX alert_events_alert_time_idx ON alert_events (alert_id, occurred_at DESC);
CREATE INDEX alert_events_time_idx ON alert_events (occurred_at DESC);

-- Provider config (including tokens/URLs when sensitive) is serialized and encrypted by the app.
CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('generic', 'telegram', 'slack', 'discord')),
    config_ciphertext BYTEA NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE alert_rule_endpoints (
    rule_id UUID NOT NULL REFERENCES alert_rules(id),
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, endpoint_id)
);

-- Transactional outbox: state transition and delivery intent are committed together.
CREATE TABLE notification_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_event_id UUID NOT NULL REFERENCES alert_events(id),
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'delivering', 'delivered', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (alert_event_id, endpoint_id)
);

CREATE INDEX notification_outbox_due_idx
    ON notification_outbox (next_attempt_at, created_at)
    WHERE status IN ('pending', 'failed');
