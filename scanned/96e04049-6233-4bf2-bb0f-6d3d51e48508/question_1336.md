# Q1336: numeric overflow / negative length - (API).ListCodespaces in api.go

## Question
Does `ListCodespaces` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L369) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [internal/codespaces/api/api.go:369](internal/codespaces/api/api.go#L369) - `(API).ListCodespaces`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
