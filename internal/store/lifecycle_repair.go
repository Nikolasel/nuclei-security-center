package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// computeLifecycleTimeline recomputes one finding's derived history (the fields
// lcDetectionExpr and the raw-occurrence join in lifecycle.go depend on) from
// only the scans that still exist. scanIDs is the target's complete scans,
// oldest first; templatesByScan holds each scan's concrete or positively
// inferred template coverage; occByScan maps a scan id to the occurrence row id
// this particular finding has in it.
//
// This does not try to reconstruct the *original* history: once a scan is
// deleted, that information is gone. It instead re-derives history purely from
// what remains, applying the same template-aware one-step-back rule
// IngestFinding uses at ingest time (times_mitigated bumps when a finding
// reappears after being missing from the immediately preceding scan that
// covered its template). A legacy scan with an occurrence is positive coverage
// evidence even when its spec predates concrete template ids. An uncovered scan
// without an occurrence is ignored rather than treated as absence.
func computeLifecycleTimeline(scanIDs []string, templateID string, templatesByScan map[string]map[string]struct{}, occByScan map[string]int64) (firstSeenScan, lastSeenScan *string, latestOccID *int64, lastCoveringScan *string, timesMitigated int) {
	wasPresent := false
	everPresent := false // true once the finding has appeared in any scan walked so far
	for _, scanID := range scanIDs {
		occID, present := occByScan[scanID]
		_, covered := templatesByScan[scanID][templateID]
		if !covered && !present {
			continue
		}
		coveringID := scanID
		lastCoveringScan = &coveringID
		if present {
			// Only a reappearance *after* an earlier presence is a mitigation
			// cycle; a finding absent from every scan up to now (including the
			// very first) is appearing for the first time, not regressing.
			if everPresent && !wasPresent {
				timesMitigated++
			}
			if firstSeenScan == nil {
				id := scanID
				firstSeenScan = &id
			}
			id := scanID
			lastSeenScan = &id
			o := occID
			latestOccID = &o
			wasPresent = true
			everPresent = true
		} else {
			wasPresent = false
		}
	}
	return firstSeenScan, lastSeenScan, latestOccID, lastCoveringScan, timesMitigated
}

// repairLifecycleForTarget recomputes computeLifecycleTimeline's fields for
// every finding_lifecycle row scoped to targetID (nil for ad-hoc/no-target
// findings), from whatever scans and occurrences remain after a scan delete. A
// row with zero surviving occurrences is deleted outright rather than reset to
// nulls: once every scan that ever observed a finding is gone, the product
// decision is that the system should behave as if it never saw that finding at
// all — including any disposition/recast overlay on it — not display an entry
// with no evidence behind it. A user who wants a finding's history to survive
// keeps the scans that back it; deleting them all is deleting that history.
// Call this inside the same transaction as the delete: the repair must be
// atomic with it, so a target's lifecycle table is never left referencing a
// scan that no longer exists.
func repairLifecycleForTarget(ctx context.Context, tx pgx.Tx, targetID *string) error {
	scanRows, err := tx.Query(ctx,
		`SELECT id,
		        ARRAY(
		            SELECT jsonb_array_elements_text(
		                CASE
		                    WHEN jsonb_typeof(spec #> '{templates,template_ids}') = 'array'
		                    THEN spec #> '{templates,template_ids}'
		                    ELSE '[]'::jsonb
		                END
		            )
		        )
		   FROM scans
		  WHERE target_id IS NOT DISTINCT FROM $1 AND state = 'complete'
		  ORDER BY created_at ASC, id ASC`,
		targetID)
	if err != nil {
		return fmt.Errorf("list surviving scans: %w", err)
	}
	defer scanRows.Close()
	var scanIDs []string
	templatesByScan := map[string]map[string]struct{}{}
	for scanRows.Next() {
		var id string
		var templateIDs []string
		if err := scanRows.Scan(&id, &templateIDs); err != nil {
			return err
		}
		scanIDs = append(scanIDs, id)
		templatesByScan[id] = make(map[string]struct{}, len(templateIDs))
		for _, templateID := range templateIDs {
			templatesByScan[id][templateID] = struct{}{}
		}
	}
	if err := scanRows.Err(); err != nil {
		return fmt.Errorf("list surviving scans: %w", err)
	}

	// Every occurrence still on record for this target's findings, across the
	// surviving scans: lifecycle id -> scan id -> occurrence id. An occurrence
	// also proves scan-wide coverage of its template for legacy specs.
	occRows, err := tx.Query(ctx,
		`SELECT finding_id, scan_id, id, template_id
		   FROM findings
		  WHERE target_id IS NOT DISTINCT FROM $1 AND finding_id IS NOT NULL`,
		targetID)
	if err != nil {
		return fmt.Errorf("list surviving occurrences: %w", err)
	}
	defer occRows.Close()
	byLifecycle := map[int64]map[string]int64{}
	for occRows.Next() {
		var lcID, occID int64
		var scanID, templateID string
		if err := occRows.Scan(&lcID, &scanID, &occID, &templateID); err != nil {
			return err
		}
		if byLifecycle[lcID] == nil {
			byLifecycle[lcID] = map[string]int64{}
		}
		byLifecycle[lcID][scanID] = occID
		if templates, ok := templatesByScan[scanID]; ok {
			templates[templateID] = struct{}{}
		}
	}
	if err := occRows.Err(); err != nil {
		return fmt.Errorf("list surviving occurrences: %w", err)
	}

	// Every lifecycle row on the target, including ones with zero surviving
	// occurrences (all their scans were deleted) — those are deleted below,
	// not merely reset.
	lcRows, err := tx.Query(ctx,
		`SELECT id, template_id FROM finding_lifecycle WHERE target_id IS NOT DISTINCT FROM $1`,
		targetID)
	if err != nil {
		return fmt.Errorf("list target lifecycle rows: %w", err)
	}
	defer lcRows.Close()
	var lcIDs []int64
	templateByLifecycle := map[int64]string{}
	for lcRows.Next() {
		var id int64
		var templateID string
		if err := lcRows.Scan(&id, &templateID); err != nil {
			return err
		}
		lcIDs = append(lcIDs, id)
		templateByLifecycle[id] = templateID
	}
	if err := lcRows.Err(); err != nil {
		return fmt.Errorf("list target lifecycle rows: %w", err)
	}

	for _, lcID := range lcIDs {
		firstSeenScan, lastSeenScan, latestOccID, lastCoveringScan, timesMitigated := computeLifecycleTimeline(
			scanIDs, templateByLifecycle[lcID], templatesByScan, byLifecycle[lcID])
		if lastSeenScan == nil {
			// No surviving scan ever observed this finding — nothing left to
			// derive a state from, so the row itself goes. findings.finding_id
			// referencing it is ON DELETE SET NULL, so any stray occurrence row
			// from a non-complete scan is simply unlinked, not an error.
			if _, err := tx.Exec(ctx, `DELETE FROM finding_lifecycle WHERE id = $1`, lcID); err != nil {
				return fmt.Errorf("drop evidence-free lifecycle %d: %w", lcID, err)
			}
			continue
		}
		// Ad-hoc lifecycle rows have no stable target scope and always remain
		// active, so they intentionally carry no comparison-scan pointer.
		if targetID == nil {
			lastCoveringScan = nil
		}
		if _, err := tx.Exec(ctx,
			`UPDATE finding_lifecycle
			    SET first_seen_scan = $1, last_seen_scan = $2, latest_occurrence_id = $3,
			        last_covering_scan = $4, times_mitigated = $5
			  WHERE id = $6`,
			firstSeenScan, lastSeenScan, latestOccID, lastCoveringScan, timesMitigated, lcID); err != nil {
			return fmt.Errorf("repair lifecycle %d: %w", lcID, err)
		}
	}
	return nil
}
