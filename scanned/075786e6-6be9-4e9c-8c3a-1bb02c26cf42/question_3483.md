# Q3483: unbounded output buffering - (API).GetCodespacesMachines in api.go

## Question
Does `GetCodespacesMachines` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L661) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [internal/codespaces/api/api.go:661](internal/codespaces/api/api.go#L661) - `(API).GetCodespacesMachines`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
