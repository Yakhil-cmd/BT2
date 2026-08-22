# Q0359: lockfile pin not enforced on update - scanInstalledSkills in update.go

## Question
Does `scanInstalledSkills` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L554) re-resolve a skill's source or version at update time, letting a transferred/renamed repository or a re-tagged release substitute different content than the pin records?

## Target
- File/function: [pkg/cmd/skills/update/update.go:554](pkg/cmd/skills/update/update.go#L554) - `scanInstalledSkills`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Transfer the skill repo to an attacker account after the victim installs it.
- Invariant to test: Updates verify the recorded source identity and content digest.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting update fails when the resolved source differs from the lockfile.
