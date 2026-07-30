// Package store is the backend's Postgres access layer and system of record.
package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store wraps a pgx connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// Options tunes how the store connects to Postgres.
type Options struct {
	// PasswordFile, if non-empty, is read on every new connection to supply the
	// password, overriding whatever password the DSN carries. This tolerates
	// rotating database credentials (e.g. AWS RDS-managed master passwords,
	// Vault dynamic secrets): as long as something keeps the file fresh, a new
	// pooled connection picks up the rotated password without a process
	// restart. The rest of the DSN (host/user/database) still comes from the
	// DSN, keeping the connection parts separate from the password source.
	PasswordFile string
}

// Open connects to Postgres and returns a Store. The caller must Close it.
func Open(ctx context.Context, dsn string) (*Store, error) {
	return OpenWithOptions(ctx, dsn, Options{})
}

// OpenWithOptions is Open with connection tuning (see Options).
func OpenWithOptions(ctx context.Context, dsn string, opts Options) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	if opts.PasswordFile != "" {
		// BeforeConnect runs before pgx establishes each new pooled connection,
		// so re-reading the file here means a rotated password is applied to
		// every fresh connection without restarting the process. Using the
		// pool's own hook keeps this a library capability rather than
		// hand-rolled reconnect/auth-failure logic (invariant #5).
		cfg.BeforeConnect = func(_ context.Context, cc *pgx.ConnConfig) error {
			pw, err := readPasswordFile(opts.PasswordFile)
			if err != nil {
				return err
			}
			cc.Password = pw
			return nil
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

// readPasswordFile reads a password from a file, trimming a single trailing
// newline (files rendered by secret stores or shell redirection commonly carry
// one). Interior and leading whitespace is preserved in case it is significant.
func readPasswordFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read database password file %q: %w", path, err)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Migrate applies any embedded migrations not yet recorded, in filename order.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			checksum_sha256 TEXT,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}
	if _, err := s.pool.Exec(ctx,
		`ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum_sha256 TEXT`,
	); err != nil {
		return fmt.Errorf("ensure migration checksums: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		sum := sha256.Sum256(sqlBytes)
		checksum := fmt.Sprintf("%x", sum)

		var recordedChecksum *string
		err = s.pool.QueryRow(ctx,
			`SELECT checksum_sha256 FROM schema_migrations WHERE version = $1`, name,
		).Scan(&recordedChecksum)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// Apply below.
		case err != nil:
			return fmt.Errorf("check migration %s: %w", name, err)
		case recordedChecksum == nil:
			// Older installations predate checksums. Establish their current
			// embedded migrations as the immutable baseline; separately named
			// repair migrations handle any already-known historical drift.
			if _, err := s.pool.Exec(ctx,
				`UPDATE schema_migrations SET checksum_sha256 = $2 WHERE version = $1`,
				name, checksum,
			); err != nil {
				return fmt.Errorf("baseline migration checksum %s: %w", name, err)
			}
			continue
		case *recordedChecksum != checksum:
			return fmt.Errorf(
				"migration %s checksum mismatch: applied migrations are immutable (recorded %s, embedded %s)",
				name, *recordedChecksum, checksum,
			)
		default:
			continue
		}
		if _, err := s.pool.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO schema_migrations (version, checksum_sha256) VALUES ($1, $2)`,
			name, checksum,
		); err != nil {
			return fmt.Errorf("record migration %s: %w", name, err)
		}
	}
	return nil
}

// ScanLink optionally ties a scan to the stored config it came from. Empty
// fields mean an ad-hoc scan not linked to a target/template set. Source
// records provenance ("adhoc" by default, "schedule" for the ticker);
// ScheduleID is set when a schedule produced the scan.
type ScanLink struct {
	TargetID      string
	TemplateSetID string
	ScanPolicyID  string
	Source        string
	ScheduleID    string
}

// CreateScan inserts a new scan in the queued state and returns its id.
func (s *Store) CreateScan(ctx context.Context, spec types.ScanSpec, link ScanLink) (string, error) {
	id := types.NewID()
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("marshal spec: %w", err)
	}
	source := link.Source
	if source == "" {
		source = "adhoc"
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO scans (id, state, spec, target_id, template_set_id, scan_policy_id, source, schedule_id, templates_commit)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, types.ScanQueued, specJSON, nullStr(link.TargetID), nullStr(link.TemplateSetID),
		nullStr(link.ScanPolicyID), source, nullStr(link.ScheduleID), nullStr(spec.Templates.TemplatesCommit),
	)
	if err != nil {
		return "", fmt.Errorf("insert scan: %w", err)
	}
	return id, nil
}

// SetScanNode records which registered scanner node was selected to run a scan
// (#107). Called at dispatch, before the node is even contacted, so the choice is
// visible even if the run then fails. nodeID may be empty (no-op) defensively.
func (s *Store) SetScanNode(ctx context.Context, scanID, nodeID string) error {
	if nodeID == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET node_id = $1 WHERE id = $2`, nodeID, scanID)
	return err
}

// MarkRunning records the node's scan id and moves the scan to running.
func (s *Store) MarkRunning(ctx context.Context, scanID, nodeScanID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET state = $1, node_scan_id = $2, started_at = now() WHERE id = $3`,
		types.ScanRunning, nodeScanID, scanID,
	)
	return err
}

// MarkFailed records a terminal failure with its reason. It never overwrites a
// scan already in a terminal state (notably cancelled): once an operator cancels
// a scan, the background poll goroutine seeing the node abort must not flip it
// back to failed.
//
// nucleiVersion/templatesCommit are recorded too when the caller has them —
// the node reports its version before the scan even starts (Runner.run captures
// it ahead of launching nuclei), so a scan that fails partway through (a
// timeout kill, in particular) still has this available; it was previously
// discarded because only MarkComplete's call site threaded it through. Either
// may be "" when truly unavailable (e.g. dispatch failed before the node ever
// responded), in which case the column is left NULL, not an empty string.
func (s *Store) MarkFailed(ctx context.Context, scanID, reason, nucleiVersion, templatesCommit string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET state = $1, error = $2, finished_at = now(),
		        nuclei_version = coalesce($4, nuclei_version), templates_commit = coalesce($5, templates_commit)
		  WHERE id = $3 AND state NOT IN ($6, $7, $8)`,
		types.ScanFailed, reason, scanID, nullStr(nucleiVersion), nullStr(templatesCommit),
		types.ScanCancelled, types.ScanComplete, types.ScanFailed,
	)
	return err
}

// SetScanVersions backfills nuclei_version/templates_commit only, leaving
// state/error/finished_at untouched — safe to call after a scan has already
// been cancelled. A user-initiated cancel (store.CancelScan) sets the terminal
// state immediately, before the background poll goroutine ever sees the node's
// final status; MarkFailed/MarkComplete then refuse to overwrite an
// already-cancelled row (see their own comments), which means the version info
// they'd otherwise carry is silently dropped. The node reports its version
// before the scan even starts, so it's known regardless of how the scan
// ended — this lets the orchestrator record it unconditionally once polling
// concludes. coalesce keeps it from ever overwriting a value another call
// already recorded.
func (s *Store) SetScanVersions(ctx context.Context, scanID, nucleiVersion, templatesCommit string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET nuclei_version = coalesce(nuclei_version, $2),
		        templates_commit = coalesce(templates_commit, $3)
		  WHERE id = $1`,
		scanID, nullStr(nucleiVersion), nullStr(templatesCommit),
	)
	return err
}

// FailOrphanedScans marks every scan left in queued/running state as failed.
// The orchestrator drives a scan from a single in-process goroutine (see
// internal/backend/orchestrator.go) with no persisted resume state, so any
// scan still queued/running when the backend starts up was orphaned by the
// previous process exiting (crash, deploy, OOM) mid-run — nothing will ever
// finish driving it otherwise, and it would sit in the UI as "running"
// forever. Called once at startup, after migrations. Returns the count
// reconciled.
func (s *Store) FailOrphanedScans(ctx context.Context, reason string) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE scans SET state = $1, error = $2, finished_at = now()
		 WHERE state IN ($3, $4)`,
		types.ScanFailed, reason, types.ScanQueued, types.ScanRunning,
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// MarkComplete records successful completion and the versions that ran. It also
// advances each matching global lifecycle row's last_covering_scan evidence
// pointer once, at completion, avoiding a per-row JSONB scan-history lookup on
// every lifecycle read. The scan must cover the template and belong to a target
// (or ad-hoc scope) that has observed this global finding before, and its
// request trace must contain the exact (template id, canonical host:port) pair.
// The exact occurrence itself is always positive coverage evidence. Absence
// without pair-level evidence fails closed.
//
// The scan transition and coverage update are one statement, so readers cannot
// observe a complete scan without its lifecycle evidence. Like MarkFailed this
// won't overwrite an already-cancelled scan, so a cancel that races an ingest
// finishing stays cancelled.
func (s *Store) MarkComplete(ctx context.Context, scanID, nucleiVersion, templatesCommit string) error {
	_, err := s.pool.Exec(ctx,
		`WITH completed_scan AS (
		    UPDATE scans
		       SET state = $1, nuclei_version = $2, templates_commit = $3, finished_at = now()
		     WHERE id = $4 AND state <> $5
		     RETURNING id, target_id, covered_endpoints, created_at
		 )
		 UPDATE finding_lifecycle lifecycle
		    SET last_covering_scan = completed_scan.id
		   FROM completed_scan
		  WHERE EXISTS (
		        SELECT 1
		          FROM findings associated
		          JOIN scans associated_scan ON associated_scan.id = associated.scan_id
		         WHERE associated.finding_id = lifecycle.id
		           AND associated_scan.target_id IS NOT DISTINCT FROM completed_scan.target_id
		    )
		    AND (
		        EXISTS (
		            SELECT 1
		              FROM findings observed
		             WHERE observed.scan_id = completed_scan.id
		               AND observed.finding_id = lifecycle.id
		        )
		        OR (
		            completed_scan.covered_endpoints IS NOT NULL
		            AND lifecycle.endpoint_key <> ''
		            AND completed_scan.covered_endpoints @>
		                jsonb_build_array(jsonb_build_object(
		                    'template_id', lifecycle.template_id,
		                    'endpoint', lifecycle.endpoint_key
		                ))
		        )
		    )
		    AND (
		        lifecycle.last_covering_scan IS NULL
		        OR EXISTS (
		            SELECT 1
		              FROM scans previous
		             WHERE previous.id = lifecycle.last_covering_scan
		               AND (previous.created_at, previous.id) <
		                   (completed_scan.created_at, completed_scan.id)
		        )
		    )`,
		types.ScanComplete, nucleiVersion, templatesCommit, scanID, types.ScanCancelled,
	)
	return err
}

// SetScanDiscovered persists the narrowed host:port list from the naabu pre-pass
// (#86). No-op for an empty list (discovery disabled or found nothing), so the
// column stays NULL rather than an empty array.
func (s *Store) SetScanDiscovered(ctx context.Context, scanID string, targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET discovered_targets = $1 WHERE id = $2`, targets, scanID)
	return err
}

// SetScanCoverage persists exact template+endpoint evidence and any fail-closed
// trace warning (#91). nil evidence remains SQL NULL; non-nil empty becomes [].
func (s *Store) SetScanCoverage(ctx context.Context, scanID string, endpoints []types.EndpointCoverage, warning string) error {
	var raw []byte
	var err error
	if endpoints != nil {
		raw, err = json.Marshal(endpoints)
		if err != nil {
			return fmt.Errorf("marshal endpoint coverage: %w", err)
		}
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE scans
		    SET covered_endpoints = $2::jsonb, coverage_warning = $3
		  WHERE id = $1`,
		scanID, raw, nullStr(warning))
	return err
}

// SetScanRawObject records the bucket key of a scan's archived raw output. The
// key is internal (a bucket path); the API exposes only ScanRow.HasRaw.
func (s *Store) SetScanRawObject(ctx context.Context, scanID, key string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET raw_object_key = $1 WHERE id = $2`, key, scanID)
	return err
}

// ScanRawKey returns the bucket key of a scan's archived raw output, or "" if the
// scan has none. ErrNotFound if the scan itself is unknown.
func (s *Store) ScanRawKey(ctx context.Context, id string) (string, error) {
	var key *string
	err := s.pool.QueryRow(ctx, `SELECT raw_object_key FROM scans WHERE id = $1`, id).Scan(&key)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", ErrNotFound
		}
		return "", err
	}
	return deref(key), nil
}

// SetScanLogObject records the bucket key of a scan's archived execution log
// (Nuclei's stdout/stderr, #94). The key is internal; the API exposes only
// ScanRow.HasLog. Independent of raw_object_key — the two are separate objects.
func (s *Store) SetScanLogObject(ctx context.Context, scanID, key string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE scans SET log_object_key = $1 WHERE id = $2`, key, scanID)
	return err
}

// ScanLogKey returns the bucket key of a scan's archived execution log, or "" if
// the scan has none. ErrNotFound if the scan itself is unknown.
func (s *Store) ScanLogKey(ctx context.Context, id string) (string, error) {
	var key *string
	err := s.pool.QueryRow(ctx, `SELECT log_object_key FROM scans WHERE id = $1`, id).Scan(&key)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", ErrNotFound
		}
		return "", err
	}
	return deref(key), nil
}

// ScanRow is a scan as returned to API callers. HasRaw reports whether the
// verbatim Nuclei output was archived (and is thus downloadable). TargetID /
// TargetName / TargetHostCount name the stored target the scan ran against (all
// zero-valued for an ad-hoc spec scan, or once the target has been deleted —
// scans.target_id is ON DELETE SET NULL so history survives). TargetHostCount
// is the real address-range size (types.HostCount), not len(target.Hosts) — a
// CIDR entry counts as its full range, not as one array element. TemplateSetID /
// TemplateSetName identify the set selected at dispatch; both are empty after
// that set is deleted. NodeID /
// NodeName identify the registered scanner node dispatch selected (#107); both
// zero-valued for a scan whose node was deleted (node_id is ON DELETE SET NULL)
// or that failed before a node was chosen. The node's token/endpoint are never
// exposed — only the human-facing name.
type ScanRow struct {
	ID              string     `json:"id"`
	State           string     `json:"state"`
	TargetID        string     `json:"target_id,omitempty"`
	TargetName      string     `json:"target_name,omitempty"`
	TargetHostCount int64      `json:"target_host_count,omitempty"`
	TemplateSetID   string     `json:"template_set_id,omitempty"`
	TemplateSetName string     `json:"template_set_name,omitempty"`
	ScanPolicyID    string     `json:"scan_policy_id,omitempty"`
	ScanPolicyName  string     `json:"scan_policy_name,omitempty"`
	NodeID          string     `json:"node_id,omitempty"`
	NodeName        string     `json:"node_name,omitempty"`
	NucleiVersion   string     `json:"nuclei_version,omitempty"`
	TemplatesCommit string     `json:"templates_commit,omitempty"`
	Error           string     `json:"error,omitempty"`
	HasRaw          bool       `json:"has_raw"`
	HasLog          bool       `json:"has_log"`
	CreatedAt       time.Time  `json:"created_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	// DiscoveredTargets is the narrowed host:port list the naabu pre-pass produced
	// (#86), persisted at completion. For a still-running scan the API layer fills
	// it from the orchestrator's live cache instead. Empty when discovery was off.
	DiscoveredTargets []string `json:"discovered_targets,omitempty"`
	// CoveredEndpoints is exact template+host:port positive evidence (#91).
	// nil means unavailable; empty means the trace was valid but nothing answered.
	CoveredEndpoints []types.EndpointCoverage `json:"covered_endpoints"`
	CoverageWarning  string                   `json:"coverage_warning,omitempty"`
	// Progress is live scan progress (#66), attached by the API layer for running
	// scans from the orchestrator's in-memory cache — never read from or written
	// to the database.
	Progress *types.ScanProgress `json:"progress,omitempty"`
}

// scanSelect is the shared projection for ScanRow reads. The LEFT JOIN surfaces
// the target's name + hosts for the scans list/detail (issue #65) without a
// second round-trip; t.hosts is NULL for an ad-hoc scan (no target), and
// scanScan expands it into a real host count rather than counting array
// elements.
const scanSelect = `
	SELECT s.id, s.state, s.target_id, t.name, t.hosts, s.template_set_id, ts.name,
	       s.scan_policy_id, sp.name, s.node_id, n.name,
	       s.nuclei_version, s.templates_commit, s.error, s.raw_object_key, s.log_object_key,
	       s.created_at, s.finished_at, s.discovered_targets,
	       s.covered_endpoints, s.coverage_warning
	  FROM scans s
	  LEFT JOIN targets t ON t.id = s.target_id
	  LEFT JOIN template_sets ts ON ts.id = s.template_set_id
	  LEFT JOIN scan_policies sp ON sp.id = s.scan_policy_id
	  LEFT JOIN scanner_nodes n ON n.id = s.node_id`

// scanClientCancellable reports the states a scan can still be cancelled from.
const scanCancellableStates = `('queued', 'running')`

func scanScan(row pgx.Row) (ScanRow, error) {
	var r ScanRow
	var targetID, targetName, templateSetID, templateSetName, scanPolicyID, scanPolicyName, nodeID, nodeName, nucleiVersion, templatesCommit, errStr, rawKey, logKey, coverageWarning *string
	var hosts []string
	var coveredJSON []byte
	if err := row.Scan(&r.ID, &r.State, &targetID, &targetName, &hosts, &templateSetID, &templateSetName,
		&scanPolicyID, &scanPolicyName, &nodeID, &nodeName,
		&nucleiVersion, &templatesCommit, &errStr, &rawKey, &logKey, &r.CreatedAt, &r.FinishedAt,
		&r.DiscoveredTargets, &coveredJSON, &coverageWarning); err != nil {
		return ScanRow{}, err
	}
	if coveredJSON != nil {
		if err := json.Unmarshal(coveredJSON, &r.CoveredEndpoints); err != nil {
			return ScanRow{}, fmt.Errorf("decode endpoint coverage: %w", err)
		}
		if r.CoveredEndpoints == nil {
			r.CoveredEndpoints = []types.EndpointCoverage{}
		}
	}
	r.TargetID = deref(targetID)
	r.TargetName = deref(targetName)
	r.TargetHostCount = types.HostCount(hosts)
	r.TemplateSetID = deref(templateSetID)
	r.TemplateSetName = deref(templateSetName)
	r.ScanPolicyID = deref(scanPolicyID)
	r.ScanPolicyName = deref(scanPolicyName)
	r.NodeID = deref(nodeID)
	r.NodeName = deref(nodeName)
	r.NucleiVersion = deref(nucleiVersion)
	r.TemplatesCommit = deref(templatesCommit)
	r.Error = deref(errStr)
	r.CoverageWarning = deref(coverageWarning)
	r.HasRaw = rawKey != nil
	r.HasLog = logKey != nil
	return r, nil
}

// GetScan returns one scan by id.
func (s *Store) GetScan(ctx context.Context, id string) (ScanRow, error) {
	r, err := scanScan(s.pool.QueryRow(ctx, scanSelect+` WHERE s.id = $1`, id))
	if err != nil {
		if err == pgx.ErrNoRows {
			return ScanRow{}, ErrNotFound
		}
		return ScanRow{}, err
	}
	return r, nil
}

// ListScans returns recent scans, newest first.
func (s *Store) ListScans(ctx context.Context, limit int) ([]ScanRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, scanSelect+` ORDER BY s.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ScanRow
	for rows.Next() {
		r, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CancelScan marks a queued/running scan as cancelled and returns its node scan
// id (for signalling the node to abort) plus whether the transition happened.
// cancelled is false when the scan wasn't in a cancellable state — the caller
// distinguishes "already terminal" (409) from "unknown" (404) via GetScan. The
// WHERE clause makes this the single authority on the state transition, so a
// racing poll can't un-cancel it.
func (s *Store) CancelScan(ctx context.Context, id, reason string) (nodeScanID string, cancelled bool, err error) {
	var node *string
	err = s.pool.QueryRow(ctx,
		`UPDATE scans SET state = $1, error = $2, finished_at = now()
		  WHERE id = $3 AND state IN `+scanCancellableStates+`
		 RETURNING node_scan_id`,
		types.ScanCancelled, reason, id,
	).Scan(&node)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	return deref(node), true, nil
}

// DeleteScan removes a scan row (its findings occurrences cascade via the FK;
// lifecycle references are set NULL). It refuses to delete a queued/running scan
// — that must be cancelled first — returning ErrConflict so the in-flight
// orchestrator goroutine never writes to a deleted row. It returns the scan's
// archived object keys (raw output and execution log, either possibly empty) so
// the caller can best-effort purge storage.
func (s *Store) DeleteScan(ctx context.Context, id string) (rawKey, logKey string, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback(ctx)

	var rkey, lkey *string
	var state string
	err = tx.QueryRow(ctx, `SELECT state, raw_object_key, log_object_key FROM scans WHERE id = $1`, id).
		Scan(&state, &rkey, &lkey)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", "", ErrNotFound
		}
		return "", "", err
	}
	if state == string(types.ScanQueued) || state == string(types.ScanRunning) {
		return "", "", ErrConflict
	}
	affectedRows, err := tx.Query(ctx,
		`WITH deleted_scan AS (
		    SELECT target_id, covered_endpoints
		      FROM scans
		     WHERE id = $1
		 )
		 SELECT lifecycle.id
		   FROM finding_lifecycle lifecycle
		   CROSS JOIN deleted_scan
		  WHERE EXISTS (
		      SELECT 1
		        FROM findings associated
		        JOIN scans associated_scan ON associated_scan.id = associated.scan_id
		       WHERE associated.finding_id = lifecycle.id
		         AND associated_scan.target_id IS NOT DISTINCT FROM deleted_scan.target_id
		  )
		    AND (
		        EXISTS (
		            SELECT 1
		              FROM findings observed
		             WHERE observed.scan_id = $1
		               AND observed.finding_id = lifecycle.id
		        )
		        OR (
		            deleted_scan.covered_endpoints IS NOT NULL
		            AND lifecycle.endpoint_key <> ''
		            AND deleted_scan.covered_endpoints @>
		                jsonb_build_array(jsonb_build_object(
		                    'template_id', lifecycle.template_id,
		                    'endpoint', lifecycle.endpoint_key
		                ))
		        )
		    )
		 UNION
		 SELECT finding_id
		   FROM findings
		  WHERE scan_id = $1 AND finding_id IS NOT NULL`,
		id)
	if err != nil {
		return "", "", fmt.Errorf("list affected lifecycle: %w", err)
	}
	var affectedLifecycle []int64
	for affectedRows.Next() {
		var lifecycleID int64
		if err := affectedRows.Scan(&lifecycleID); err != nil {
			affectedRows.Close()
			return "", "", err
		}
		affectedLifecycle = append(affectedLifecycle, lifecycleID)
	}
	if err := affectedRows.Err(); err != nil {
		affectedRows.Close()
		return "", "", fmt.Errorf("list affected lifecycle: %w", err)
	}
	affectedRows.Close()
	if _, err := tx.Exec(ctx, `DELETE FROM scans WHERE id = $1`, id); err != nil {
		return "", "", err
	}
	// The delete just cascaded this scan's findings occurrences and (via
	// ON DELETE SET NULL) nulled any first_seen_scan/last_seen_scan/
	// latest_occurrence_id pointer to it. Left alone, a finding whose
	// times_mitigated / first_seen_scan survive from history that no longer
	// exists would show a detection state (e.g. "resurfaced") the remaining
	// scans can't actually justify. Recompute those fields for the affected
	// global lifecycle rows from only the scans that still exist, so every
	// finding's story stays explainable from what's currently visible.
	if err := repairLifecycleFindings(ctx, tx, affectedLifecycle); err != nil {
		return "", "", fmt.Errorf("repair lifecycle: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}
	return deref(rkey), deref(lkey), nil
}

// FindingRow is a single per-scan occurrence as returned to API callers (the
// scan-detail view). FindingID records its global lifecycle association, but the
// scan UI opens this occurrence itself so exact historical evidence is never
// substituted with a newer merged result.
type FindingRow struct {
	ID         int64     `json:"id"`
	ScanID     string    `json:"scan_id"`
	TargetID   *string   `json:"target_id,omitempty"`
	FindingID  *int64    `json:"finding_id,omitempty"`
	TemplateID string    `json:"template_id"`
	Name       string    `json:"name"`
	Severity   string    `json:"severity"`
	Host       string    `json:"host"`
	MatchedAt  string    `json:"matched_at"`
	Type       string    `json:"type"`
	CVE        []string  `json:"cve"`
	Tags       []string  `json:"tags"`
	CreatedAt  time.Time `json:"created_at"`
}

// FindingFilter narrows and pages a findings query. All filter fields are
// optional; Limit/Offset drive server-side pagination.
type FindingFilter struct {
	ScanID     string
	Query      string   // substring match on vulnerability name OR template id
	Severities []string // any-of (e.g. ["critical","high"])
	Host       string   // substring match
	CVE        string   // substring match on any of the finding's CVE ids
	Tag        string   // exact tag membership
	Limit      int
	Offset     int
}

// severityOrder ranks findings so the most severe sort first, server-side.
const severityOrder = `CASE lower(severity)
	WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
	WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END`

// ListFindings returns a page of findings (severity-sorted, then newest first)
// plus the total count matching the filter (ignoring Limit/Offset).
func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]FindingRow, int, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	var conds []string
	var args []any
	// push appends an arg and returns its 1-based placeholder index.
	push := func(val any) int {
		args = append(args, val)
		return len(args)
	}
	if f.ScanID != "" {
		conds = append(conds, fmt.Sprintf("scan_id = $%d", push(f.ScanID)))
	}
	if f.Query != "" {
		n := push("%" + f.Query + "%")
		conds = append(conds, fmt.Sprintf("(name ILIKE $%d OR template_id ILIKE $%d)", n, n))
	}
	if len(f.Severities) > 0 {
		lowered := make([]string, len(f.Severities))
		for i, s := range f.Severities {
			lowered[i] = strings.ToLower(s)
		}
		conds = append(conds, fmt.Sprintf("lower(severity) = ANY($%d)", push(lowered)))
	}
	if f.Host != "" {
		conds = append(conds, fmt.Sprintf("host ILIKE $%d", push("%"+f.Host+"%")))
	}
	if f.CVE != "" {
		conds = append(conds, fmt.Sprintf(
			"EXISTS (SELECT 1 FROM unnest(cve) c WHERE c ILIKE $%d)", push("%"+f.CVE+"%")))
	}
	if f.Tag != "" {
		conds = append(conds, fmt.Sprintf("$%d = ANY(tags)", push(f.Tag)))
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM findings "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limitPH := push(f.Limit)
	offsetPH := push(f.Offset)
	query := fmt.Sprintf(
		`SELECT id, scan_id, target_id, finding_id, template_id, name, severity, host, matched_at, type, cve, tags, created_at
		 FROM findings %s ORDER BY %s DESC, id DESC LIMIT $%d OFFSET $%d`,
		where, severityOrder, limitPH, offsetPH)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []FindingRow
	for rows.Next() {
		var fr FindingRow
		if err := rows.Scan(&fr.ID, &fr.ScanID, &fr.TargetID, &fr.FindingID, &fr.TemplateID, &fr.Name, &fr.Severity,
			&fr.Host, &fr.MatchedAt, &fr.Type, &fr.CVE, &fr.Tags, &fr.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, fr)
	}
	return out, total, rows.Err()
}

// OccurrenceDetail is one exact, immutable Nuclei result. Unlike a lifecycle
// detail it never substitutes the latest globally merged result.
type OccurrenceDetail struct {
	FindingRow
	Raw json.RawMessage `json:"raw"`
}

// GetOccurrence returns one immutable scan occurrence by id.
func (s *Store) GetOccurrence(ctx context.Context, id int64) (OccurrenceDetail, error) {
	var detail OccurrenceDetail
	var raw string
	err := s.pool.QueryRow(ctx,
		`SELECT id, scan_id, target_id, finding_id, template_id, name, severity,
		        host, matched_at, type, cve, tags, created_at,
		        COALESCE(raw_line, raw::text)
		   FROM findings
		  WHERE id = $1`,
		id).Scan(
		&detail.ID, &detail.ScanID, &detail.TargetID, &detail.FindingID,
		&detail.TemplateID, &detail.Name, &detail.Severity, &detail.Host,
		&detail.MatchedAt, &detail.Type, &detail.CVE, &detail.Tags,
		&detail.CreatedAt, &raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OccurrenceDetail{}, ErrNotFound
		}
		return OccurrenceDetail{}, err
	}
	detail.Raw = json.RawMessage(raw)
	return detail, nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
