# Q3752: width/emoji handling desync - setDefaultRun in setdefault.go

## Question
Can zero-width, RTL-override, or combining characters in a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes rendered by `setDefaultRun` in [pkg/cmd/repo/setdefault/setdefault.go](pkg/cmd/repo/setdefault/setdefault.go#L126) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/repo/setdefault/setdefault.go:126](pkg/cmd/repo/setdefault/setdefault.go#L126) - `setDefaultRun`
- Entrypoint: gh repo setdefault
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
