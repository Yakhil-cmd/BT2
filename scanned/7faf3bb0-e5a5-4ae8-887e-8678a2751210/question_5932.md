# Q5932: lockfile pin not enforced on update - isNotFound in discovery.go

## Question
Does `isNotFound` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L327) re-resolve a skill's source or version at update time, letting a transferred/renamed repository or a re-tagged release substitute different content than the pin records?

## Target
- File/function: [internal/skills/discovery/discovery.go:327](internal/skills/discovery/discovery.go#L327) - `isNotFound`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Transfer the skill repo to an attacker account after the victim installs it.
- Invariant to test: Updates verify the recorded source identity and content digest.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting update fails when the resolved source differs from the lockfile.
