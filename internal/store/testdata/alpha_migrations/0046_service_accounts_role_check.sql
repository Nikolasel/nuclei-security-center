-- Service-account role drives every RBAC decision (#215). The application
-- allowlist is currently the only enforcement; add a database CHECK so a
-- future writer that bypasses isAssignableRole cannot persist an arbitrary
-- role string. satisfies() would rank an unknown role as 0 (inert, not
-- escalated), but the schema should make the allowed set explicit, matching
-- the six other enum columns that already have CHECK constraints.
ALTER TABLE service_accounts
    ADD CONSTRAINT service_accounts_role_check
    CHECK ((role = ANY (ARRAY['viewer'::text, 'operator'::text, 'admin'::text])));
