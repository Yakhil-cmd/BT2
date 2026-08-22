# Q0513: host taken from repo remote - editRun in edit.go

## Question
Does `editRun` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L118) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:118](pkg/cmd/gist/edit/edit.go#L118) - `editRun`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run gh gist edit inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
