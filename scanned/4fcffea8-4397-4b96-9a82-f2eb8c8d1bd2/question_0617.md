# Q0617: nil dereference panic on hostile field - isUsernameValid in invoker.go

## Question
Can an attacker-shaped response make `isUsernameValid` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L313) dereference a nil pointer or index out of range, crashing gh mid-operation (leaving partial state on disk)?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:313](internal/codespaces/rpc/invoker.go#L313) - `isUsernameValid`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return a response with nested nulls or empty arrays where gh expects data.
- Invariant to test: All response-derived structures are checked before dereference.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz the decoder with mutated payloads asserting no panic.
