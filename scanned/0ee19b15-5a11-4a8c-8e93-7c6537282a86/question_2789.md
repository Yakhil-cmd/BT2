# Q2789: unauthenticated fallback on error - newCpCmd in ssh.go

## Question
When authentication fails inside `newCpCmd` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L710), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:710](pkg/cmd/codespace/ssh.go#L710) - `newCpCmd`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
