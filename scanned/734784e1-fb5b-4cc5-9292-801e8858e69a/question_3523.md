# Q3523: unauthenticated fallback on error - filterCodespacesByRepoOwner in common.go

## Question
When authentication fails inside `filterCodespacesByRepoOwner` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L262), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/codespace/common.go:262](pkg/cmd/codespace/common.go#L262) - `filterCodespacesByRepoOwner`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
