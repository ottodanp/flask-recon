CREATE TABLE IF NOT EXISTS "actors"
(
    "actor_id"     SERIAL PRIMARY KEY,
    "host"         VARCHAR(255) NOT NULL,
    "flagged"      BOOLEAN      NOT NULL DEFAULT FALSE,
    "threat_level" INTEGER      NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS "services"
(
    "service_id" SERIAL PRIMARY KEY,
    "actor_id"   INTEGER      NOT NULL,
    "service"    VARCHAR(255) NOT NULL,
    "port"       INTEGER      NOT NULL,
    FOREIGN KEY ("actor_id") REFERENCES "actors" ("actor_id")
);

CREATE TABLE IF NOT EXISTS "requests"
(
    "request_id"   SERIAL PRIMARY KEY,
    "actor_id"     INTEGER      NOT NULL,
    "timestamp"    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "method"       VARCHAR(255) NOT NULL,
    "path"         VARCHAR(255) NOT NULL,
    "body"         TEXT,
    "headers"      TEXT,
    "query_string" TEXT,
    "port"         INTEGER      NOT NULL,
    "acceptable"   BOOLEAN      NOT NULL,
    "threat_level" INTEGER      NOT NULL DEFAULT 0,
    FOREIGN KEY ("actor_id") REFERENCES "actors" ("actor_id")
);

CREATE TABLE IF NOT EXISTS "honeypots"
(
    "honeypot_id"    SERIAL PRIMARY KEY,
    "file_name"      VARCHAR(255) NOT NULL,
    "dummy_contents" TEXT         NOT NULL
);

CREATE TABLE IF NOT EXISTS "analysed_requests"
(
    "analysis_id" SERIAL PRIMARY KEY,
    "request_id"  INTEGER NOT NULL,
    "analysis"    TEXT,
    "notes"       TEXT,
    FOREIGN KEY ("request_id") REFERENCES "requests" ("request_id")
);

CREATE TABLE IF NOT EXISTS "analysed_actors"
(
    "analysis_id" SERIAL PRIMARY KEY,
    "actor_id"    INTEGER NOT NULL,
    "analysis"    TEXT,
    "notes"       TEXT,
    FOREIGN KEY ("actor_id") REFERENCES "actors" ("actor_id")
);

CREATE TABLE IF NOT EXISTS "connect_targets"
(
    "target_id" SERIAL PRIMARY KEY,
    "url"       VARCHAR(255) NOT NULL,
    "body"      TEXT
);
