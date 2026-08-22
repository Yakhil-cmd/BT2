# Q3731: local repo state trusted for host decisions - populateResolvedRemotes in client.go

## Question
Does `populateResolvedRemotes` in [git/client.go](git/client.go#L1037) read `.git/config` or ref state from the current directory (a repository the attacker published and the victim cloned) and use it for an authenticated decision?

## Target
- File/function: [git/client.go:1037](git/client.go#L1037) - `populateResolvedRemotes`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Ship a repo whose config seeds the value gh trusts.
- Invariant to test: Repository-derived values are treated as untrusted input.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with hostile config asserting no credential use.
