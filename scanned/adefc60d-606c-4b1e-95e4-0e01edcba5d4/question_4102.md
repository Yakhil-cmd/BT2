# Q4102: unbounded output buffering - (IOStreams).startTextualProgressIndicator in iostreams.go

## Question
Does `startTextualProgressIndicator` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L342) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/iostreams/iostreams.go:342](pkg/iostreams/iostreams.go#L342) - `(IOStreams).startTextualProgressIndicator`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
