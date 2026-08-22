# Q0631: connection retried against a fallback host - (API).CreateCodespace in api.go

## Question
On failure, does `CreateCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L895) retry the connection against a host from the error/response payload?

## Target
- File/function: [internal/codespaces/api/api.go:895](internal/codespaces/api/api.go#L895) - `(API).CreateCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Fail the first connection and supply a fallback host.
- Invariant to test: Retries reuse the originally validated endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry endpoint equals the original.
