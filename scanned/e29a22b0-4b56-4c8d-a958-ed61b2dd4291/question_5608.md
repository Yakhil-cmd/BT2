# Q5608: scope/permission check bypass - (invoker).appendMetadata in invoker.go

## Question
Does `appendMetadata` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L164) make a security decision from a scope/permission value returned by the server (or absent header) that codespace/API response fields and everything the codespace-side process sends back can influence?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:164](internal/codespaces/rpc/invoker.go#L164) - `(invoker).appendMetadata`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return an inflated or empty `X-OAuth-Scopes` from an attacker-controlled host so gh skips a confirmation.
- Invariant to test: Local privilege decisions never depend on unauthenticated, attacker-supplied response data.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: httpmock test with forged scope headers asserting gh still enforces the check.
