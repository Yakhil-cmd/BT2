# Q0389: skill install executes content - parseGitHubURL in publish.go

## Question
Does `parseGitHubURL` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L1006) execute, source, or hand to an interpreter any part of a downloaded skill during install or preview, before an explicit user decision?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:1006](pkg/cmd/skills/publish/publish.go#L1006) - `parseGitHubURL`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill containing an executable payload and get the victim to install or preview it.
- Invariant to test: Installation only writes validated files; nothing is executed.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Integration test installing a hostile skill fixture asserting no execution.
