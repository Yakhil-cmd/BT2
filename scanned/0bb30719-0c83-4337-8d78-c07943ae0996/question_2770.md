# Q2770: session state cached across codespaces - (API).GetCodespacesPermissionsCheck in api.go

## Question
Can connection state or credentials cached by `GetCodespacesPermissionsCheck` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L704) be reused for a different codespace or owner?

## Target
- File/function: [internal/codespaces/api/api.go:704](internal/codespaces/api/api.go#L704) - `(API).GetCodespacesPermissionsCheck`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Connect to an attacker-shared codespace then to the victim's own.
- Invariant to test: Cached session material is keyed by codespace identity and never reused.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting cache keys include the codespace id and owner.
