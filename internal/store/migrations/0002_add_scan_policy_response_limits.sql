-- Add per-response read/save caps to scan policies (#274).
-- Each column caps bytes nuclei buffers per request (-response-size-read
-- / -response-size-save, defaults 10 MiB/1 MiB). NULL ⇒ use nuclei's default
-- (omitted flag), so existing policies stay valid without a backfill.
ALTER TABLE scan_policies
    ADD COLUMN response_size_read integer,
    ADD COLUMN response_size_save integer;

-- Positive when set (buildArgs omits <=0, but keep storage sane).
ALTER TABLE scan_policies
    ADD CONSTRAINT scan_policies_response_size_read_check CHECK (response_size_read IS NULL OR response_size_read > 0),
    ADD CONSTRAINT scan_policies_response_size_save_check CHECK (response_size_save IS NULL OR response_size_save > 0);
