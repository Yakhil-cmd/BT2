# Q1081: unbounded output buffering - renderSelectedFilePreview in preview.go

## Question
Does `renderSelectedFilePreview` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L384) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:384](pkg/cmd/skills/preview/preview.go#L384) - `renderSelectedFilePreview`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
