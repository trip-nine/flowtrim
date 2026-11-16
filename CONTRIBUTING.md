# Contributing

1. `make lint test` must pass. CI also runs `go-licenses` and rejects GPL/AGPL dependencies.
2. Any new reduction feature needs a test proving which detection signal it preserves.
3. Clean-room only: do not copy code, schemas or field names from proprietary collectors.
4. Commits are signed off (`git commit -s`, DCO).
