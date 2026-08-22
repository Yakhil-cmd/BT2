# Q2534: unbounded output buffering - renderDiagnosticsPlain in publish.go

## Question
Does `renderDiagnosticsPlain` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L1118) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:1118](pkg/cmd/skills/publish/publish.go#L1118) - `renderDiagnosticsPlain`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
