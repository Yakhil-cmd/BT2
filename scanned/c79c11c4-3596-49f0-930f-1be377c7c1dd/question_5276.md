# Q5276: host taken from repo remote - mightBeGHESUser in cmd.go

## Question
Does `mightBeGHESUser` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L482) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [internal/ghcmd/cmd.go:482](internal/ghcmd/cmd.go#L482) - `mightBeGHESUser`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run gh extension install inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
