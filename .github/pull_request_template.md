## What

<!-- One or two sentences: what does this change do? -->

## Why

<!-- Link the issue this closes (`Closes #NNN`), or explain the motivation. -->

## How verified

- [ ] `gofmt -l .` clean, `go vet ./...`, `go build ./...`
- [ ] `go test ./...` (note which parts were exercised if integration tests were skipped)
- [ ] `cd web && npm run build` (if the SPA changed)
- [ ] Behavior checked against the running stack / browser (if user-visible)

## Notes for review

<!-- Invariant or docs impact, migration/fold-into-baseline notes, follow-ups intentionally skipped. -->
