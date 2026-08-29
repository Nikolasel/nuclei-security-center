# Alpha migration reference chain

These SQL files are a test-only reference chain used to verify that the fresh
beta baseline produces the intended pre-beta schema. They are not a supported
upgrade path for released deployments; alpha databases are rejected at startup.

The chain is now **sealed**: beta shipped, so a schema change must NOT append a fixture or
move the count / SHA-256 pin in `internal/store/migration_integration_test.go`. Ship a new
numbered file under `internal/store/migrations/` instead. The baseline and the complete
reference chain must stay semantically equivalent — the equivalence test verifies this.
