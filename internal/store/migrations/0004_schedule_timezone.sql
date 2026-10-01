-- Per-schedule IANA timezone for cron evaluation (#329).
-- next_run_at stays timestamptz (UTC instant); the zone is only used when
-- compiling the cron so "0 3 * * *" means 03:00 in that zone, including DST.
-- Existing rows keep UTC, matching the previous process-local (container UTC)
-- behavior, except a valid robfig TZ= / CRON_TZ= prefix is copied into timezone
-- and stripped from cron so those schedules keep firing in the prefixed zone.

ALTER TABLE schedules
    ADD COLUMN timezone text NOT NULL DEFAULT 'UTC';

COMMENT ON COLUMN schedules.timezone IS 'IANA timezone name used to evaluate cron; UTC when omitted. The only zone: cron must not carry TZ=/CRON_TZ=.';

UPDATE schedules AS s
SET timezone = p.zone,
    cron = p.rest
FROM (
    SELECT id,
           substring(cron FROM '^(?:TZ|CRON_TZ)=(\S+)') AS zone,
           regexp_replace(cron, '^(TZ|CRON_TZ)=\S+\s+', '') AS rest
    FROM schedules
    WHERE cron ~ '^(TZ|CRON_TZ)=\S+\s+\S'
) AS p
WHERE s.id = p.id
  AND p.zone IS NOT NULL
  AND p.zone <> 'Local'
  AND p.rest <> ''
  AND EXISTS (SELECT 1 FROM pg_timezone_names n WHERE n.name = p.zone);
