# Q0936: unbounded output buffering - (Manager).installBin in manager.go

## Question
Does `installBin` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L282) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/extension/manager.go:282](pkg/cmd/extension/manager.go#L282) - `(Manager).installBin`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
