# Q0057: unbounded output buffering - switchRun in switch.go

## Question
Does `switchRun` in [pkg/cmd/auth/switch/switch.go](pkg/cmd/auth/switch/switch.go#L77) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/auth/switch/switch.go:77](pkg/cmd/auth/switch/switch.go#L77) - `switchRun`
- Entrypoint: gh auth switch
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
