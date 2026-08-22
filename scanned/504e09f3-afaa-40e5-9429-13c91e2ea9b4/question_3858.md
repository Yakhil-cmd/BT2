# Q3858: host taken from repo remote - ValidateSupportedHost in source.go

## Question
Does `ValidateSupportedHost` in [internal/skills/source/source.go](internal/skills/source/source.go#L56) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [internal/skills/source/source.go:56](internal/skills/source/source.go#L56) - `ValidateSupportedHost`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run gh skills install inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
