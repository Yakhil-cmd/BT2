# Q4939: session state cached across codespaces - getPortPairs in ports.go

## Question
Can connection state or credentials cached by `getPortPairs` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L372) be reused for a different codespace or owner?

## Target
- File/function: [pkg/cmd/codespace/ports.go:372](pkg/cmd/codespace/ports.go#L372) - `getPortPairs`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Connect to an attacker-shared codespace then to the victim's own.
- Invariant to test: Cached session material is keyed by codespace identity and never reused.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting cache keys include the codespace id and owner.
