# Q5613: YAML/frontmatter expansion or injection - isUsernameValid in invoker.go

## Question
Does the frontmatter/YAML parsing in `isUsernameValid` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L313) allow anchors/aliases, duplicate keys, or unexpected fields from remote content to override a validated value?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:313](internal/codespaces/rpc/invoker.go#L313) - `isUsernameValid`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a skill/template whose frontmatter redefines a field gh already validated.
- Invariant to test: Parsing is strict: known fields only, duplicates and aliases rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with duplicate/alias frontmatter asserting an error.
