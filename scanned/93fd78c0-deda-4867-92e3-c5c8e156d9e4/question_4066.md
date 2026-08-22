# Q4066: numeric overflow / negative length - truncateAsUTF16 in logs.go

## Question
Does `truncateAsUTF16` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L342) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [pkg/cmd/run/view/logs.go:342](pkg/cmd/run/view/logs.go#L342) - `truncateAsUTF16`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
