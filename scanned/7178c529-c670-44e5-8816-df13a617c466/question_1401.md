# Q1401: nested archive re-extraction - extractZip in copilot.go

## Question
Does content extracted by `extractZip` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L378) get fed into a further parser/extractor without re-applying the destination checks?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:378](pkg/cmd/copilot/copilot.go#L378) - `extractZip`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Nest an archive inside the published artifact so the inner extraction runs with weaker validation.
- Invariant to test: Every extraction layer applies the same root confinement.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test a nested archive fixture asserting inner entries are also confined.
