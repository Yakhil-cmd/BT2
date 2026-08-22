# Q3024: width/emoji handling desync - cloneRun in clone.go

## Question
Can zero-width, RTL-override, or combining characters in a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes rendered by `cloneRun` in [pkg/cmd/repo/clone/clone.go](pkg/cmd/repo/clone/clone.go#L111) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/repo/clone/clone.go:111](pkg/cmd/repo/clone/clone.go#L111) - `cloneRun`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
