# Q1340: unbounded output buffering - (API).StopCodespace in api.go

## Question
Does `StopCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L619) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [internal/codespaces/api/api.go:619](internal/codespaces/api/api.go#L619) - `(API).StopCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
