# Q3381: unbounded output buffering - (Untrusted).String in untrusted.go

## Question
Does `String` in [pkg/iostreams/untrusted.go](pkg/iostreams/untrusted.go#L38) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/iostreams/untrusted.go:38](pkg/iostreams/untrusted.go#L38) - `(Untrusted).String`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
