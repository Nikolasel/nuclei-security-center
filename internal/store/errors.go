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
