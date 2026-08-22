# Q4894: OAuth callback/state validation - connect in invoker.go

## Question
Does the browser/device flow driven by `connect` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L77) accept a callback or device response without binding state, PKCE, or the originating host?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:77](internal/codespaces/rpc/invoker.go#L77) - `connect`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Feed the local callback listener a forged request so gh stores an attacker-issued token for the victim's host.
- Invariant to test: Callbacks are accepted only with a matching state and from the flow gh initiated.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test posting a forged callback with a wrong state and asserting rejection.
