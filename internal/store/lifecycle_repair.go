package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
	"github.com/jackc/pgx/v5"
)

// computeLifecycleTimeline recomputes one global finding's scan-derived history.
// scanIDs is oldest first; covered reports whether a scan carried both relevant
// template coverage and an occurrence-provenance scope associated with this
// finding. Incomplete scans should return false for absent findings so they do
// not create mitigation gaps. occByScan maps scans that actually observed this
// exact result variant to their immutable occurrence id.
func computeLifecycleTimeline(scanIDs []string, covered func(string) bool, occByScan map[string]int64) (firstSeenScan, lastSeenScan *string, latestOccID *int64, lastCoveringScan *string, timesMitigated int) {
	wasPresent := false
	everPresent := false
	for _, scanID := range scanIDs {
		occID, present := occByScan[scanID]
		if !covered(scanID) {
			continue
		}
		coveringID := scanID
		lastCoveringScan = &coveringID
		if present {
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

// repairLifecycleFindings rebuilds only the global lifecycle rows affected by a
// scan deletion. A scan covers a global finding when its trace proves the exact
// template+endpoint pair in one of the target/ad-hoc scopes that has observed
// that finding and its result ingest was complete. This preserves the existing
// fail-closed behavior for unknown or incomplete coverage while allowing
// observations from overlapping target records to share one lifecycle.
//
// A row with no surviving occurrence is deleted: deleting every scan that
// observed a finding deletes the evidence and its analyst overlay with it.
func repairLifecycleFindings(ctx context.Context, tx pgx.Tx, lifecycleIDs []int64) error {
	if len(lifecycleIDs) == 0 {
		return nil
	}

	occRows, err := tx.Query(ctx,
		`SELECT occurrence.finding_id, occurrence.scan_id, occurrence.id,
		        observed_scan.target_id
		   FROM findings occurrence
		   JOIN scans observed_scan ON observed_scan.id = occurrence.scan_id
		  WHERE occurrence.finding_id = ANY($1)`,
		lifecycleIDs)
	if err != nil {
		return fmt.Errorf("list surviving occurrences: %w", err)
	}
	byLifecycle := map[int64]map[string]int64{}
	targetsByLifecycle := map[int64]map[string]struct{}{}
	for occRows.Next() {
		var lcID, occID int64
		var scanID string
		var targetID *string
		if err := occRows.Scan(&lcID, &scanID, &occID, &targetID); err != nil {
			occRows.Close()
			return err
		}
		if byLifecycle[lcID] == nil {
			byLifecycle[lcID] = map[string]int64{}
		}
		byLifecycle[lcID][scanID] = occID
		if targetsByLifecycle[lcID] == nil {
			targetsByLifecycle[lcID] = map[string]struct{}{}
		}
		targetsByLifecycle[lcID][targetScopeKey(targetID)] = struct{}{}
	}
	if err := occRows.Err(); err != nil {
		occRows.Close()
		return fmt.Errorf("list surviving occurrences: %w", err)
	}
	occRows.Close()

	// Restrict history to target/ad-hoc scopes that still have an occurrence of
	// one of the affected global findings. Exact observations are positive
	// evidence; otherwise a scan covers only an exact template+endpoint pair.
	scanRows, err := tx.Query(ctx,
		`SELECT scans.id, scans.target_id, scans.covered_endpoints,
		        scans.skipped_finding_count
		   FROM scans
		  WHERE scans.state = 'complete'
		    AND EXISTS (
		        SELECT 1
		          FROM findings associated
		          JOIN scans observed_scan ON observed_scan.id = associated.scan_id
		         WHERE associated.finding_id = ANY($1)
		           AND observed_scan.target_id IS NOT DISTINCT FROM scans.target_id
		    )
		  ORDER BY scans.created_at ASC, scans.id ASC`,
		lifecycleIDs)
	if err != nil {
		return fmt.Errorf("list surviving scans: %w", err)
	}
	var scanIDs []string
	targetByScan := map[string]string{}
	coverageByScan := map[string]map[types.EndpointCoverage]struct{}{}
	skippedByScan := map[string]int{}
	for scanRows.Next() {
		var id string
		var targetID *string
		var coveredJSON []byte
		var skippedCount int
		if err := scanRows.Scan(&id, &targetID, &coveredJSON, &skippedCount); err != nil {
			scanRows.Close()
			return err
		}
		scanIDs = append(scanIDs, id)
		targetByScan[id] = targetScopeKey(targetID)
		skippedByScan[id] = skippedCount
		if coveredJSON != nil {
			var endpoints []types.EndpointCoverage
			if err := json.Unmarshal(coveredJSON, &endpoints); err != nil {
				// Persisted telemetry is evidence, not authority over whether scan
				// deletion can proceed. Treat malformed historical JSON as unknown
				// coverage so repair fails closed for this scan.
				continue
			}
			coverageByScan[id] = make(map[types.EndpointCoverage]struct{}, len(endpoints))
			for _, endpoint := range endpoints {
				if endpoint.TemplateID == "" || endpoint.Endpoint == "" {
					continue
				}
				coverageByScan[id][endpoint] = struct{}{}
			}
		}
	}
	if err := scanRows.Err(); err != nil {
		scanRows.Close()
		return fmt.Errorf("list surviving scans: %w", err)
	}
	scanRows.Close()

	lcRows, err := tx.Query(ctx,
		`SELECT id, template_id, endpoint_key FROM finding_lifecycle WHERE id = ANY($1)`,
		lifecycleIDs)
	if err != nil {
		return fmt.Errorf("list affected lifecycle rows: %w", err)
	}
	templateByLifecycle := map[int64]string{}
	endpointByLifecycle := map[int64]string{}
	var existingIDs []int64
	for lcRows.Next() {
		var id int64
		var templateID, endpointKey string
		if err := lcRows.Scan(&id, &templateID, &endpointKey); err != nil {
			lcRows.Close()
			return err
		}
		existingIDs = append(existingIDs, id)
		templateByLifecycle[id] = templateID
		endpointByLifecycle[id] = endpointKey
	}
	if err := lcRows.Err(); err != nil {
		lcRows.Close()
		return fmt.Errorf("list affected lifecycle rows: %w", err)
	}
	lcRows.Close()

	for _, lcID := range existingIDs {
		templateID := templateByLifecycle[lcID]
		covered := func(scanID string) bool {
			if _, ok := targetsByLifecycle[lcID][targetByScan[scanID]]; !ok {
				return false
			}
			if _, present := byLifecycle[lcID][scanID]; present {
				return true
			}
			if skippedByScan[scanID] > 0 {
				return false
			}
			coverage, known := coverageByScan[scanID]
			if !known || endpointByLifecycle[lcID] == "" {
				return false
			}
			_, ok := coverage[types.EndpointCoverage{
				TemplateID: templateID,
				Endpoint:   endpointByLifecycle[lcID],
			}]
			return ok
		}
		firstSeenScan, lastSeenScan, latestOccID, lastCoveringScan, timesMitigated :=
			computeLifecycleTimeline(scanIDs, covered, byLifecycle[lcID])
		if lastSeenScan == nil {
			if _, err := tx.Exec(ctx, `DELETE FROM finding_lifecycle WHERE id = $1`, lcID); err != nil {
				return fmt.Errorf("drop evidence-free lifecycle %d: %w", lcID, err)
			}
			continue
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

func targetScopeKey(targetID *string) string {
	if targetID == nil {
		return ""
	}
	return *targetID
}
