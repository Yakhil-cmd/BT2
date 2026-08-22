# Q1387: numeric overflow / negative length - ParseSessionIDFromURL in capi.go

## Question
Does `ParseSessionIDFromURL` in [pkg/cmd/agent-task/shared/capi.go](pkg/cmd/agent-task/shared/capi.go#L78) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [pkg/cmd/agent-task/shared/capi.go:78](pkg/cmd/agent-task/shared/capi.go#L78) - `ParseSessionIDFromURL`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
