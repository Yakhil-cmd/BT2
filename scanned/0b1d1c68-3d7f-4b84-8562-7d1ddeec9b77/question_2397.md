# Q2397: nested archive re-extraction - downloadAsset in http.go

## Question
Does content extracted by `downloadAsset` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L79) get fed into a further parser/extractor without re-applying the destination checks?

## Target
- File/function: [pkg/cmd/extension/http.go:79](pkg/cmd/extension/http.go#L79) - `downloadAsset`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Nest an archive inside the published artifact so the inner extraction runs with weaker validation.
- Invariant to test: Every extraction layer applies the same root confinement.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test a nested archive fixture asserting inner entries are also confined.
