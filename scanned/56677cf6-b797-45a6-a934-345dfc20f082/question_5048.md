# Q5048: host taken from repo remote - logoutRun in logout.go

## Question
Does `logoutRun` in [pkg/cmd/auth/logout/logout.go](pkg/cmd/auth/logout/logout.go#L79) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [pkg/cmd/auth/logout/logout.go:79](pkg/cmd/auth/logout/logout.go#L79) - `logoutRun`
- Entrypoint: gh auth logout
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run gh auth logout inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
