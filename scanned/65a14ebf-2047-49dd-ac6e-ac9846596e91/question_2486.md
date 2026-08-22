# Q2486: YAML/frontmatter expansion or injection - existingSkillPrompt in install.go

## Question
Does the frontmatter/YAML parsing in `existingSkillPrompt` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1089) allow anchors/aliases, duplicate keys, or unexpected fields from remote content to override a validated value?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1089](pkg/cmd/skills/install/install.go#L1089) - `existingSkillPrompt`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill/template whose frontmatter redefines a field gh already validated.
- Invariant to test: Parsing is strict: known fields only, duplicates and aliases rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with duplicate/alias frontmatter asserting an error.
