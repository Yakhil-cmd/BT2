# Q4900: regex catastrophic backtracking - isUsernameValid in invoker.go

## Question
Can codespace/API response fields and everything the codespace-side process sends back feed a pathological string to the regular expression used in `isUsernameValid` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L313) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:313](internal/codespaces/rpc/invoker.go#L313) - `isUsernameValid`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run gh codespace ssh.
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
