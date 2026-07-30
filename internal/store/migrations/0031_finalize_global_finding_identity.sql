-- Forward-only cleanup for databases that exercised an earlier, unmerged 0030
-- revision while PR #152 was under review. The final 0030 drops these helpers
-- itself; IF EXISTS keeps this migration harmless on a clean installation.
--
-- This separate file also demonstrates the migration immutability rule:
-- never rely on editing an already-recorded filename to update a database.
DROP FUNCTION IF EXISTS nsc_finding_result_discriminator(JSONB);
DROP FUNCTION IF EXISTS nsc_finding_key_part(TEXT);
