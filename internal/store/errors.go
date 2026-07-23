package store

import "errors"

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a write violates a uniqueness constraint
// (e.g. a duplicate target/template-set name).
var ErrConflict = errors.New("conflict")

// ErrInvalidRef is returned when a write references a row that doesn't exist
// (a foreign-key violation — e.g. a schedule pointing at a missing target).
var ErrInvalidRef = errors.New("invalid reference")

// ErrNodeOverlap is returned when a scanner node's CIDRs overlap another node's
// (#22). Node ranges must be disjoint so a target maps to exactly one node.
var ErrNodeOverlap = errors.New("scanner node CIDRs overlap another node")

// ErrLastCatchAll is returned when deleting a scanner node would leave no
// catch-all (no-CIDR) node, so hostname/unmatched targets would be undispatchable.
var ErrLastCatchAll = errors.New("cannot delete the last catch-all scanner node")

// ErrNoNodeForTarget is returned by dispatch selection when no scanner node
// serves a target's IP and there is no catch-all node to fall back to.
var ErrNoNodeForTarget = errors.New("no scanner node serves the target")

// ErrTemplateReadOnly is returned when a write targets an upstream template.
// Upstream rows are owned by the sync (#85) — only custom templates are
// editable through the API, so editing/deleting an upstream one is refused.
var ErrTemplateReadOnly = errors.New("upstream templates are read-only")

// ErrTemplateSetNotLegacy is returned when conversion is requested for a set
// that already uses explicit membership.
var ErrTemplateSetNotLegacy = errors.New("template set is already explicit")

// ErrNoTemplateMatches leaves a legacy set untouched when its retired filter
// resolves to no active catalog templates.
var ErrNoTemplateMatches = errors.New("legacy filter matches no active templates")

// ErrTemplateSetLegacy keeps membership edits read-only until the filter is
// atomically converted, avoiding partially materialized legacy sets.
var ErrTemplateSetLegacy = errors.New("legacy filter set must be converted first")
