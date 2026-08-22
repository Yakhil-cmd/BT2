# Q5252: unbounded output buffering - fetchLatestRelease in http.go

## Question
Does `fetchLatestRelease` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L119) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/extension/http.go:119](pkg/cmd/extension/http.go#L119) - `fetchLatestRelease`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
