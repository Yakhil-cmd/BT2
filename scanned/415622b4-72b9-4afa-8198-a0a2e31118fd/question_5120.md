# Q5120: host taken from repo remote - NewCmdApi in api.go

## Question
Does `NewCmdApi` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L66) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [pkg/cmd/api/api.go:66](pkg/cmd/api/api.go#L66) - `NewCmdApi`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run gh api inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
