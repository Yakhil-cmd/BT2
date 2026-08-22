# Q5944: frontmatter fields drive execution or trust - walkTree in discovery.go

## Question
Can frontmatter fields parsed by `walkTree` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L881) (name, command, allowed-tools, source, version) redirect gh to another source, another directory, or a command?

## Target
- File/function: [internal/skills/discovery/discovery.go:881](internal/skills/discovery/discovery.go#L881) - `walkTree`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose frontmatter overrides the field gh trusts.
- Invariant to test: Frontmatter is data only; identity and paths come from the validated source coordinates.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting hostile frontmatter cannot change the install target.
