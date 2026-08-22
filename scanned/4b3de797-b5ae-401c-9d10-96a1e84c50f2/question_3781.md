# Q3781: width/emoji handling desync - printLinkedBranches in develop.go

## Question
Can zero-width, RTL-override, or combining characters in a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes rendered by `printLinkedBranches` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L342) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:342](pkg/cmd/issue/develop/develop.go#L342) - `printLinkedBranches`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
