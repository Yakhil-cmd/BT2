# Q3961: lockfile pin not enforced on update - renderDiagnosticsTTY in publish.go

## Question
Does `renderDiagnosticsTTY` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L1056) re-resolve a skill's source or version at update time, letting a transferred/renamed repository or a re-tagged release substitute different content than the pin records?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:1056](pkg/cmd/skills/publish/publish.go#L1056) - `renderDiagnosticsTTY`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Transfer the skill repo to an attacker account after the victim installs it.
- Invariant to test: Updates verify the recorded source identity and content digest.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting update fails when the resolved source differs from the lockfile.
