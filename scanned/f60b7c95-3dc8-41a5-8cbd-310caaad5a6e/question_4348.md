# Q4348: width/emoji handling desync - GetCurrentLogin in login_flow.go

## Question
Can zero-width, RTL-override, or combining characters in a hostname, OAuth/device response, or git credential-protocol input the attacker supplies rendered by `GetCurrentLogin` in [pkg/cmd/auth/shared/login_flow.go](pkg/cmd/auth/shared/login_flow.go#L253) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/auth/shared/login_flow.go:253](pkg/cmd/auth/shared/login_flow.go#L253) - `GetCurrentLogin`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
