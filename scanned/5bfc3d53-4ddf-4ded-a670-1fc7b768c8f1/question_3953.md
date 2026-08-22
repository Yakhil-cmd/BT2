# Q3953: frontmatter fields drive execution or trust - checkTagProtection in publish.go

## Question
Can frontmatter fields parsed by `checkTagProtection` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L764) (name, command, allowed-tools, source, version) redirect gh to another source, another directory, or a command?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:764](pkg/cmd/skills/publish/publish.go#L764) - `checkTagProtection`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose frontmatter overrides the field gh trusts.
- Invariant to test: Frontmatter is data only; identity and paths come from the validated source coordinates.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting hostile frontmatter cannot change the install target.
