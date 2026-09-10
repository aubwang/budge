CREATE TABLE requests(
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id), service_id TEXT NOT NULL REFERENCES services(id), revision INTEGER NOT NULL, permission_id TEXT NOT NULL REFERENCES permissions(id), key_hash TEXT NOT NULL, submission_digest TEXT NOT NULL, snapshot_digest TEXT NOT NULL, snapshot BLOB, status TEXT NOT NULL CHECK(status IN ('pending_approval','queued','dispatching','completed','failed','outcome_unknown','denied','expired','cancelled')), expires INTEGER NOT NULL, created INTEGER NOT NULL DEFAULT(unixepoch()), finished INTEGER, result BLOB, reason TEXT NOT NULL DEFAULT '', UNIQUE(device_id,key_hash)
);
CREATE INDEX request_work ON requests(status,expires);
CREATE TABLE approvals(request_id TEXT PRIMARY KEY REFERENCES requests(id), decided_by_owner_id TEXT NOT NULL REFERENCES owners(id), digest TEXT NOT NULL, decision TEXT NOT NULL, decided_at INTEGER NOT NULL DEFAULT(unixepoch()));
