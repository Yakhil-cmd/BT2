# Q1555: width/emoji handling desync - printHeaders in api.go

## Question
Can zero-width, RTL-override, or combining characters in a repo/remote/host string or API response field the attacker publishes rendered by `printHeaders` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L613) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/api/api.go:613](pkg/cmd/api/api.go#L613) - `printHeaders`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
