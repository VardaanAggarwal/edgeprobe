CREATE TABLE scan (
    id          UUID PRIMARY KEY,
    url         VARCHAR(2100) NOT NULL,
    host        VARCHAR(255)  NOT NULL,
    started_at  TIMESTAMPTZ   NOT NULL,
    duration_ms BIGINT        NOT NULL,
    score       INTEGER       NOT NULL CHECK (score BETWEEN 0 AND 100),
    grade       VARCHAR(2)    NOT NULL,
    fail_count  INTEGER       NOT NULL,
    warn_count  INTEGER       NOT NULL
);

-- History queries filter by host and sort newest first.
CREATE INDEX idx_scan_host_started_at ON scan (host, started_at DESC);
CREATE INDEX idx_scan_started_at ON scan (started_at DESC);

CREATE TABLE finding (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     UUID         NOT NULL REFERENCES scan (id) ON DELETE CASCADE,
    position    INTEGER      NOT NULL,
    check_id    VARCHAR(64)  NOT NULL,
    code        VARCHAR(128) NOT NULL,
    outcome     VARCHAR(8)   NOT NULL,
    severity    VARCHAR(8)   NOT NULL,
    title       VARCHAR(500) NOT NULL,
    detail      TEXT         NOT NULL,
    remediation TEXT         NOT NULL,
    UNIQUE (scan_id, position)
);

-- "Which sites failed HSTS this week" style questions.
CREATE INDEX idx_finding_code_outcome ON finding (code, outcome);
