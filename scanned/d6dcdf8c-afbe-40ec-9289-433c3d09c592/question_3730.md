# Q3730: YAML/frontmatter expansion or injection - parseRemoteURLOrName in client.go

## Question
Does the frontmatter/YAML parsing in `parseRemoteURLOrName` in [git/client.go](git/client.go#L1026) allow anchors/aliases, duplicate keys, or unexpected fields from remote content to override a validated value?

## Target
- File/function: [git/client.go:1026](git/client.go#L1026) - `parseRemoteURLOrName`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a skill/template whose frontmatter redefines a field gh already validated.
- Invariant to test: Parsing is strict: known fields only, duplicates and aliases rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with duplicate/alias frontmatter asserting an error.
