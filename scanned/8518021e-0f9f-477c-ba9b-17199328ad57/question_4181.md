# Q4181: account/host switch persists wrong credentials - connect in invoker.go

## Question
Can `connect` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L77) be driven to write or activate credentials under a host/account key different from the one that was authenticated?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:77](internal/codespaces/rpc/invoker.go#L77) - `connect`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Complete a login flow against an attacker-run GHES host that reports a github.com-looking identity.
- Invariant to test: The stored key is derived from the URL actually authenticated against, not from server-provided identity.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a server returning a mismatched login/host asserting the config key equals the dialed host.
