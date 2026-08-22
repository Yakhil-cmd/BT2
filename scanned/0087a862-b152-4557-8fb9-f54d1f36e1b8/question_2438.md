# Q2438: YAML/frontmatter expansion or injection - readFrom in lockfile.go

## Question
Does the frontmatter/YAML parsing in `readFrom` in [internal/skills/lockfile/lockfile.go](internal/skills/lockfile/lockfile.go#L53) allow anchors/aliases, duplicate keys, or unexpected fields from remote content to override a validated value?

## Target
- File/function: [internal/skills/lockfile/lockfile.go:53](internal/skills/lockfile/lockfile.go#L53) - `readFrom`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill/template whose frontmatter redefines a field gh already validated.
- Invariant to test: Parsing is strict: known fields only, duplicates and aliases rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with duplicate/alias frontmatter asserting an error.
