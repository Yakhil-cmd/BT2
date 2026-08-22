# Q2053: host-scoped client leaked into another flow - (API).StartCodespace in api.go

## Question
Can the client/transport constructed in `StartCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L586) (with its auth round-tripper) be reused by a later flow whose target host came from codespace/API response fields and everything the codespace-side process sends back?

## Target
- File/function: [internal/codespaces/api/api.go:586](internal/codespaces/api/api.go#L586) - `(API).StartCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
