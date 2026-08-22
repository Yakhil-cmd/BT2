# Q2348: local repo state trusted for host decisions - NewCmdDevelop in develop.go

## Question
Does `NewCmdDevelop` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L40) read `.git/config` or ref state from the current directory (a repository the attacker published and the victim cloned) and use it for an authenticated decision?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:40](pkg/cmd/issue/develop/develop.go#L40) - `NewCmdDevelop`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Ship a repo whose config seeds the value gh trusts.
- Invariant to test: Repository-derived values are treated as untrusted input.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with hostile config asserting no credential use.
