# Q1286: unbounded output buffering - PrintMessage in display.go

## Question
Does `PrintMessage` in [pkg/cmd/pr/shared/display.go](pkg/cmd/pr/shared/display.go#L62) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/pr/shared/display.go:62](pkg/cmd/pr/shared/display.go#L62) - `PrintMessage`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
