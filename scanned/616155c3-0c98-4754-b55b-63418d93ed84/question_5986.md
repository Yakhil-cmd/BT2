# Q5986: frontmatter fields drive execution or trust - filterHiddenDirSkills in preview.go

## Question
Can frontmatter fields parsed by `filterHiddenDirSkills` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L423) (name, command, allowed-tools, source, version) redirect gh to another source, another directory, or a command?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:423](pkg/cmd/skills/preview/preview.go#L423) - `filterHiddenDirSkills`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose frontmatter overrides the field gh trusts.
- Invariant to test: Frontmatter is data only; identity and paths come from the validated source coordinates.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting hostile frontmatter cannot change the install target.
