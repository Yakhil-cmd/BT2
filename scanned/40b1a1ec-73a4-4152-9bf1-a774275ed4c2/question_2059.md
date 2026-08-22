# Q2059: session state cached across codespaces - (API).CreateCodespace in api.go

## Question
Can connection state or credentials cached by `CreateCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L895) be reused for a different codespace or owner?

## Target
- File/function: [internal/codespaces/api/api.go:895](internal/codespaces/api/api.go#L895) - `(API).CreateCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Connect to an attacker-shared codespace then to the victim's own.
- Invariant to test: Cached session material is keyed by codespace identity and never reused.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting cache keys include the codespace id and owner.
