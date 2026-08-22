# Q1727: skill install executes content - (Skill).DisplayName in discovery.go

## Question
Does `DisplayName` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L60) execute, source, or hand to an interpreter any part of a downloaded skill during install or preview, before an explicit user decision?

## Target
- File/function: [internal/skills/discovery/discovery.go:60](internal/skills/discovery/discovery.go#L60) - `(Skill).DisplayName`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill containing an executable payload and get the victim to install or preview it.
- Invariant to test: Installation only writes validated files; nothing is executed.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Integration test installing a hostile skill fixture asserting no execution.
