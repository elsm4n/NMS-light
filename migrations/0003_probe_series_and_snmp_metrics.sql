ALTER TABLE devices
    ADD COLUMN tcp_probe_ports INTEGER[] NOT NULL DEFAULT '{}'::INTEGER[]
        CHECK (
            cardinality(tcp_probe_ports) <= 32
            AND 0 < ALL (tcp_probe_ports)
            AND 65536 > ALL (tcp_probe_ports)
        );

ALTER TABLE alert_rules
    ADD COLUMN series_key TEXT
        CHECK (series_key IS NULL OR (length(series_key) BETWEEN 1 AND 128));

ALTER TABLE alerts
    DROP CONSTRAINT alerts_rule_id_device_id_key,
    ADD COLUMN series_key TEXT NOT NULL DEFAULT '';

ALTER TABLE alerts
    ADD CONSTRAINT alerts_rule_device_series_key UNIQUE (rule_id, device_id, series_key);

CREATE TABLE snmp_interface_counters (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    if_index INTEGER NOT NULL CHECK (if_index > 0),
    direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
    counter_value TEXT NOT NULL CHECK (counter_value ~ '^[0-9]{1,20}$'),
    counter_bits SMALLINT NOT NULL CHECK (counter_bits IN (32, 64)),
    observed_at TIMESTAMPTZ NOT NULL,
    sys_uptime_ticks BIGINT,
    discontinuity_ticks BIGINT,
    PRIMARY KEY (device_id, if_index, direction)
);
