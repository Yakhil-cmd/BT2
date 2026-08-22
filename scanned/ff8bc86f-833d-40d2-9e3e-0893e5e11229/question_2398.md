# Q2398: numeric overflow / negative length - fetchLatestRelease in http.go

## Question
Does `fetchLatestRelease` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L119) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [pkg/cmd/extension/http.go:119](pkg/cmd/extension/http.go#L119) - `fetchLatestRelease`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
