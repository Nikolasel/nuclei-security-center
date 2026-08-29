## What

<!-- One or two sentences: what does this change do? -->

## Why

<!-- Link the issue this closes (`Closes #NNN`), or explain the motivation. -->

## How verified

- [ ] `gofmt -l .` clean, `go vet ./...`, `go build ./...`
- [ ] `go test ./...` — and `go test -race -count=1 ./...` with `NSC_TEST_DATABASE_URL` set (what CI runs) if the change touches store/DB or concurrency paths
- [ ] `cd web && npm run build` (if the SPA changed)
- [ ] Behavior checked against the running stack / browser (if user-visible)

## Notes for review

<!-- Invariant or docs impact, migration (new numbered file / repair-forward) notes, follow-ups intentionally skipped. -->
