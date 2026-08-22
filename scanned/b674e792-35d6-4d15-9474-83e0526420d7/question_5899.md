# Q5899: unbounded output buffering - NewCmdExtension in extension.go

## Question
Does `NewCmdExtension` in [pkg/cmd/root/extension.go](pkg/cmd/root/extension.go#L22) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/root/extension.go:22](pkg/cmd/root/extension.go#L22) - `NewCmdExtension`
- Entrypoint: gh root extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
