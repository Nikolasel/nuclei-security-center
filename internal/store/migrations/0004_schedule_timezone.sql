-- Per-schedule IANA timezone for cron evaluation (#329).
-- next_run_at stays timestamptz (UTC instant); the zone is only used when
-- compiling the cron so "0 3 * * *" means 03:00 in that zone, including DST.
-- Existing rows keep UTC, matching the previous process-local (container UTC) behavior.

ALTER TABLE schedules
    ADD COLUMN timezone text NOT NULL DEFAULT 'UTC';

COMMENT ON COLUMN schedules.timezone IS 'IANA timezone name used to evaluate cron; UTC when omitted';
