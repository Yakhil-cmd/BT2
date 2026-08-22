# Q0129: numeric overflow / negative length - parseErrorResponse in api.go

## Question
Does `parseErrorResponse` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L651) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [pkg/cmd/api/api.go:651](pkg/cmd/api/api.go#L651) - `parseErrorResponse`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
