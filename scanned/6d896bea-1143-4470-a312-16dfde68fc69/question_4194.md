# Q4194: YAML/frontmatter expansion or injection - (API).GetCodespace in api.go

## Question
Does the frontmatter/YAML parsing in `GetCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L539) allow anchors/aliases, duplicate keys, or unexpected fields from remote content to override a validated value?

## Target
- File/function: [internal/codespaces/api/api.go:539](internal/codespaces/api/api.go#L539) - `(API).GetCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a skill/template whose frontmatter redefines a field gh already validated.
- Invariant to test: Parsing is strict: known fields only, duplicates and aliases rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with duplicate/alias frontmatter asserting an error.
