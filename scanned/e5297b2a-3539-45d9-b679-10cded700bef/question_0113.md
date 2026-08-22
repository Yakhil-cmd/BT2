# Q0113: nested archive re-extraction - HttpClientFunc in default.go

## Question
Does content extracted by `HttpClientFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L188) get fed into a further parser/extractor without re-applying the destination checks?

## Target
- File/function: [pkg/cmd/factory/default.go:188](pkg/cmd/factory/default.go#L188) - `HttpClientFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Nest an archive inside the published artifact so the inner extraction runs with weaker validation.
- Invariant to test: Every extraction layer applies the same root confinement.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test a nested archive fixture asserting inner entries are also confined.
