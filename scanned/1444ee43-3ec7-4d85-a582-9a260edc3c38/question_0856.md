# Q0856: local repo state trusted for host decisions - parseWorktrees in client.go

## Question
Does `parseWorktrees` in [git/client.go](git/client.go#L294) read `.git/config` or ref state from the current directory (a repository the attacker published and the victim cloned) and use it for an authenticated decision?

## Target
- File/function: [git/client.go:294](git/client.go#L294) - `parseWorktrees`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Ship a repo whose config seeds the value gh trusts.
- Invariant to test: Repository-derived values are treated as untrusted input.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with hostile config asserting no credential use.
