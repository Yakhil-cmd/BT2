# Q3346: nested archive re-extraction - newZipLogMap in logs.go

## Question
Does content extracted by `newZipLogMap` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L166) get fed into a further parser/extractor without re-applying the destination checks?

## Target
- File/function: [pkg/cmd/run/view/logs.go:166](pkg/cmd/run/view/logs.go#L166) - `newZipLogMap`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Nest an archive inside the published artifact so the inner extraction runs with weaker validation.
- Invariant to test: Every extraction layer applies the same root confinement.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test a nested archive fixture asserting inner entries are also confined.
