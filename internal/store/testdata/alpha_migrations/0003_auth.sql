-- Phase 1: OIDC/BFF authentication. The backend is a confidential OIDC client;
-- browser sessions live server-side and the SPA only ever holds an opaque,
-- httpOnly cookie. Roles come from the IdP (a groups/roles claim), so there is
-- no in-app user management -- `users` is just an identity registry for audit
-- and for populating `created_by`.

-- users: one row per distinct OIDC subject we've seen, upserted on each login.
-- roles is a snapshot of the last login's mapped roles (for display/audit only;
-- authorization always uses the live session's roles).
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY,
    subject       TEXT NOT NULL,
    email         TEXT,
    name          TEXT,
    roles         TEXT[] NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_subject_key ON users (subject);

-- sessions: server-side session store (the BFF's session custody). id is a
-- high-entropy opaque token carried verbatim in the httpOnly session cookie;
-- identity is denormalized so auth middleware is a single indexed lookup.
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    subject    TEXT NOT NULL,
    email      TEXT,
    name       TEXT,
    roles      TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

-- auth_flows: short-lived per-login state for the authorization-code flow. The
-- opaque `state` doubles as CSRF protection; nonce and the PKCE verifier are
-- kept server-side (never in the browser). Rows are consumed on callback and
-- swept on expiry.
CREATE TABLE IF NOT EXISTS auth_flows (
    state         TEXT PRIMARY KEY,
    nonce         TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    return_to     TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL
);
