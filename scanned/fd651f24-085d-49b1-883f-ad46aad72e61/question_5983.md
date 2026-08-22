# Q5983: host taken from repo remote - renderAllFiles in preview.go

## Question
Does `renderAllFiles` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L267) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:267](pkg/cmd/skills/preview/preview.go#L267) - `renderAllFiles`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run gh skills preview inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
