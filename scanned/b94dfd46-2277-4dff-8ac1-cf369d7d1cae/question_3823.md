# Q3823: unbounded output buffering - repoExists in http.go

## Question
Does `repoExists` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L16) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/extension/http.go:16](pkg/cmd/extension/http.go#L16) - `repoExists`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
