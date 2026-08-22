# Q2269: unbounded output buffering - printHeaders in api.go

## Question
Does `printHeaders` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L613) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/api/api.go:613](pkg/cmd/api/api.go#L613) - `printHeaders`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
