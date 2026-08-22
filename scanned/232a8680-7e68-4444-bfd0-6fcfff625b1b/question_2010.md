# Q2010: copy-to-clipboard / OSC 52 path - printTable in output.go

## Question
Can content rendered by `printTable` in [pkg/cmd/pr/checks/output.go](pkg/cmd/pr/checks/output.go#L94) write to the victim's clipboard via OSC 52, staging a command for the next paste?

## Target
- File/function: [pkg/cmd/pr/checks/output.go:94](pkg/cmd/pr/checks/output.go#L94) - `printTable`
- Entrypoint: gh pr checks
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a body containing an OSC 52 payload.
- Invariant to test: OSC sequences are stripped from all remote text.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting OSC 52 bytes never appear in output.
