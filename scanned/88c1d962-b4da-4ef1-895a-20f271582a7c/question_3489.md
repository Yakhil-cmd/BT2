# Q3489: width/emoji handling desync - (API).DeleteCodespace in api.go

## Question
Can zero-width, RTL-override, or combining characters in codespace/API response fields and everything the codespace-side process sends back rendered by `DeleteCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L1051) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [internal/codespaces/api/api.go:1051](internal/codespaces/api/api.go#L1051) - `(API).DeleteCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
