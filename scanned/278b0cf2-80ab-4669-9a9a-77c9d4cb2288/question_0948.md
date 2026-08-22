# Q0948: unauthenticated fallback on error - (Manager).goBinScaffolding in manager.go

## Question
When authentication fails inside `goBinScaffolding` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L670), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/extension/manager.go:670](pkg/cmd/extension/manager.go#L670) - `(Manager).goBinScaffolding`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
