# Q2415: unbounded output buffering - Main in cmd.go

## Question
Does `Main` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L52) accumulate the full attacker-controlled body/table in memory before printing, allowing a huge published object to exhaust the victim's RAM?

## Target
- File/function: [internal/ghcmd/cmd.go:52](internal/ghcmd/cmd.go#L52) - `Main`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an object with an enormous field the victim lists or views.
- Invariant to test: Rendering streams with bounded buffers.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Benchmark/test with a very large field asserting bounded allocation or an error.
