# Q3494: width/emoji handling desync - (API).withRetry in api.go

## Question
Can zero-width, RTL-override, or combining characters in codespace/API response fields and everything the codespace-side process sends back rendered by `withRetry` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L1299) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [internal/codespaces/api/api.go:1299](internal/codespaces/api/api.go#L1299) - `(API).withRetry`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
