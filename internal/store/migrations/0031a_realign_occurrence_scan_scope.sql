-- Prepare historical occurrence provenance for the composite scope constraint.
--
-- Before 0032, findings.target_id had no FK. Deleting a target set the owning
-- scan's target_id to NULL but left its occurrence copies pointing at the
-- deleted target. scans.target_id is now the declared scope authority, so
-- realign every historical copy before adding the constraint. This deliberately
-- means deleted targets disappear from lifecycle target projection/filtering,
-- matching the ON UPDATE CASCADE behavior enforced for future deletions.
UPDATE findings occurrence
   SET target_id = observed_scan.target_id
  FROM scans observed_scan
 WHERE observed_scan.id = occurrence.scan_id
   AND occurrence.target_id IS DISTINCT FROM observed_scan.target_id;
