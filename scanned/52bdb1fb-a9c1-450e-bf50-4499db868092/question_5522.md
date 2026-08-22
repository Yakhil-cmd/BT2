# Q5522: numeric overflow / negative length - (Untrusted).UnmarshalJSON in untrusted.go

## Question
Does `UnmarshalJSON` in [pkg/iostreams/untrusted.go](pkg/iostreams/untrusted.go#L63) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [pkg/iostreams/untrusted.go:63](pkg/iostreams/untrusted.go#L63) - `(Untrusted).UnmarshalJSON`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
