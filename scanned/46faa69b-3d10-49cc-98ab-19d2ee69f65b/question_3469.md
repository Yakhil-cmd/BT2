# Q3469: connection retried against a fallback host - (invoker).StartJupyterServer in invoker.go

## Question
On failure, does `StartJupyterServer` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L169) retry the connection against a host from the error/response payload?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:169](internal/codespaces/rpc/invoker.go#L169) - `(invoker).StartJupyterServer`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Fail the first connection and supply a fallback host.
- Invariant to test: Retries reuse the originally validated endpoint.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the retry endpoint equals the original.
