# Q3172: YAML/frontmatter expansion or injection - fetchDescription in discovery.go

## Question
Does the frontmatter/YAML parsing in `fetchDescription` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L648) allow anchors/aliases, duplicate keys, or unexpected fields from remote content to override a validated value?

## Target
- File/function: [internal/skills/discovery/discovery.go:648](internal/skills/discovery/discovery.go#L648) - `fetchDescription`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill/template whose frontmatter redefines a field gh already validated.
- Invariant to test: Parsing is strict: known fields only, duplicates and aliases rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with duplicate/alias frontmatter asserting an error.
