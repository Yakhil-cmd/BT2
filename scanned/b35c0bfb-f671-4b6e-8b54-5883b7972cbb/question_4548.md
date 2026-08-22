# Q4548: numeric overflow / negative length - getExtensions in browse.go

## Question
Does `getExtensions` in [pkg/cmd/extension/browse/browse.go](pkg/cmd/extension/browse/browse.go#L330) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [pkg/cmd/extension/browse/browse.go:330](pkg/cmd/extension/browse/browse.go#L330) - `getExtensions`
- Entrypoint: gh extension browse
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
