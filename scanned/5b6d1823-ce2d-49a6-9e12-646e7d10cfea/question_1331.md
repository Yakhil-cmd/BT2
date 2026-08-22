# Q1331: numeric overflow / negative length - isUsernameValid in invoker.go

## Question
Does `isUsernameValid` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L313) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:313](internal/codespaces/rpc/invoker.go#L313) - `isUsernameValid`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
