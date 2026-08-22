# Q2108: unbounded output buffering - runCopilot in copilot.go

## Question
Does `runCopilot` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L134) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:134](pkg/cmd/copilot/copilot.go#L134) - `runCopilot`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
