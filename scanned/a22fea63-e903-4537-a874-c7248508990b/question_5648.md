# Q5648: unauthenticated fallback on error - (App).UpdatePortVisibility in ports.go

## Question
When authentication fails inside `UpdatePortVisibility` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L233), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/codespace/ports.go:233](pkg/cmd/codespace/ports.go#L233) - `(App).UpdatePortVisibility`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
