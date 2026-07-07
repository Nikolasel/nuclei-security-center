package store

import "errors"

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a write violates a uniqueness constraint
// (e.g. a duplicate target/template-set name).
var ErrConflict = errors.New("conflict")
