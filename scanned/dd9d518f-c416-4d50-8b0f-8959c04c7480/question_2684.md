# Q2684: unbounded output buffering - BinaryContentType in content.go

## Question
Does `BinaryContentType` in [pkg/iostreams/content.go](pkg/iostreams/content.go#L24) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/iostreams/content.go:24](pkg/iostreams/content.go#L24) - `BinaryContentType`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
