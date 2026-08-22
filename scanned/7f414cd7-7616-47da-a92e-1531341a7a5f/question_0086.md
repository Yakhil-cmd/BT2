# Q0086: width/emoji handling desync - ExtractHeader in http_client.go

## Question
Can zero-width, RTL-override, or combining characters in a repo/remote/host string or API response field the attacker publishes rendered by `ExtractHeader` in [api/http_client.go](api/http_client.go#L175) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [api/http_client.go:175](api/http_client.go#L175) - `ExtractHeader`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
