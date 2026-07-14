-- Service-account API tokens for headless/automation access (#70). The OIDC/BFF
-- session cookie is the only path for interactive users; unattended callers
-- (cron/CI pushing GET /api/findings/export into DefectDojo, etc.) need a
-- scoped, revocable, individually-auditable credential instead of scripting a
-- human login. These identities are NSC-local (not a second SSO surface), so
-- they live here in Postgres rather than the IdP.
--
-- The token is shown to the operator exactly once at creation/rotation; only its
-- SHA-256 hash is stored (the token is high-entropy from a CSPRNG, so a fast
-- hash + constant-time-equivalent exact-hash lookup is the right primitive — no
-- password KDF needed). token_prefix is the cleartext leading chars, kept only
-- so a human can tell which stored token a row corresponds to.
CREATE TABLE IF NOT EXISTS service_accounts (
    id           UUID PRIMARY KEY,
    name         TEXT NOT NULL,
    role         TEXT NOT NULL,                     -- viewer | operator | admin
    token_hash   TEXT NOT NULL,                     -- sha256(token), hex
    token_prefix TEXT NOT NULL,                     -- leading chars, for display
    created_by   TEXT,                              -- OIDC subject that minted it
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,                       -- NULL = no expiry (discouraged)
    last_used_at TIMESTAMPTZ                        -- best-effort touch on auth
);

-- Names are the human handle; keep them unique so rotation/revocation is
-- unambiguous.
CREATE UNIQUE INDEX IF NOT EXISTS service_accounts_name_key ON service_accounts (name);

-- Auth resolves a presented token by its hash on every automation call — the hot
-- path, so index it. Unique because two accounts sharing a token hash would be a
-- collision (or a bug).
CREATE UNIQUE INDEX IF NOT EXISTS service_accounts_token_hash_key ON service_accounts (token_hash);
