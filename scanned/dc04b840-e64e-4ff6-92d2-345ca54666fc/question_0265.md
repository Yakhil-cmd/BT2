# Q0265: YAML/frontmatter expansion or injection - getExtensions in browse.go

## Question
Does the frontmatter/YAML parsing in `getExtensions` in [pkg/cmd/extension/browse/browse.go](pkg/cmd/extension/browse/browse.go#L330) allow anchors/aliases, duplicate keys, or unexpected fields from remote content to override a validated value?

## Target
- File/function: [pkg/cmd/extension/browse/browse.go:330](pkg/cmd/extension/browse/browse.go#L330) - `getExtensions`
- Entrypoint: gh extension browse
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a skill/template whose frontmatter redefines a field gh already validated.
- Invariant to test: Parsing is strict: known fields only, duplicates and aliases rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with duplicate/alias frontmatter asserting an error.
