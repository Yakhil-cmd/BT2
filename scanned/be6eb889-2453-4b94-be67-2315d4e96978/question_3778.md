# Q3778: gh-specific post-clone git commands - developRunCreate in develop.go

## Question
Can attacker-controlled repository metadata (default branch name, remote list, upstream) influence the extra git commands gh runs after gh issue develop through `developRunCreate` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L201)?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:201](pkg/cmd/issue/develop/develop.go#L201) - `developRunCreate`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Set a default branch named `--exec=...` or containing shell-relevant characters.
- Invariant to test: Names from remote data are validated as refs and passed after `--`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile default-branch names.
