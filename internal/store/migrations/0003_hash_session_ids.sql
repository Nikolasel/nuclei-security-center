-- Browser session cookies are bearer credentials. Keep only their SHA-256
-- representation in the database; the plaintext value remains in the browser.
-- pgcrypto supplies digest() for the one-time conversion of existing beta rows.
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

UPDATE sessions
   SET id = encode(public.digest(id, 'sha256'), 'hex');
