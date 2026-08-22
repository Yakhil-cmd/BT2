# Q1693: host taken from repo remote - getExtensions in browse.go

## Question
Does `getExtensions` in [pkg/cmd/extension/browse/browse.go](pkg/cmd/extension/browse/browse.go#L330) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [pkg/cmd/extension/browse/browse.go:330](pkg/cmd/extension/browse/browse.go#L330) - `getExtensions`
- Entrypoint: gh extension browse
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run gh extension browse inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
