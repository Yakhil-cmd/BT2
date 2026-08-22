# Q4896: session state cached across codespaces - (invoker).StartJupyterServer in invoker.go

## Question
Can connection state or credentials cached by `StartJupyterServer` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L169) be reused for a different codespace or owner?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:169](internal/codespaces/rpc/invoker.go#L169) - `(invoker).StartJupyterServer`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Connect to an attacker-shared codespace then to the victim's own.
- Invariant to test: Cached session material is keyed by codespace identity and never reused.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting cache keys include the codespace id and owner.
