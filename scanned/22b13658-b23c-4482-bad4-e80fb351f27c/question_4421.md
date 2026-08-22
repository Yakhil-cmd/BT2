# Q4421: host taken from repo remote - CredentialPatternFromHost in client.go

## Question
Does `CredentialPatternFromHost` in [git/client.go](git/client.go#L134) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [git/client.go:134](git/client.go#L134) - `CredentialPatternFromHost`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run gh repo clone inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
