# Q0628: logs rendered raw - (API).GetCodespacesPermissionsCheck in api.go

## Question
Does `GetCodespacesPermissionsCheck` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L704) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [internal/codespaces/api/api.go:704](internal/codespaces/api/api.go#L704) - `(API).GetCodespacesPermissionsCheck`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
