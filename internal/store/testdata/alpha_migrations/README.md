# Alpha migration reference chain

These SQL files are a test-only reference chain used to verify that the fresh
beta baseline produces the intended pre-beta schema. They are not a supported
upgrade path for released deployments; alpha databases are rejected at startup.

Before beta release, an intentional schema change may append a numbered fixture
and update the count and SHA-256 pin in `internal/store/migration_integration_test.go`.
Keep the baseline and the complete reference chain semantically equivalent.
