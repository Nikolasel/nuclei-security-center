-- Discovered endpoints from the naabu pre-pass (#86). When a scan runs port
-- discovery, the scanner node narrows the target to the live host:port pairs it
-- finds and hands that list to Nuclei. Persist it here so the UI can show which
-- endpoints were actually scanned, after the scan completes (while running, the
-- orchestrator serves it from its in-memory cache). NULL/empty = discovery was
-- disabled or found nothing. TEXT[] matches targets.hosts.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS discovered_targets TEXT[];
