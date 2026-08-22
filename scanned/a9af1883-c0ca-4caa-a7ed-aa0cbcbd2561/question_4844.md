# Q4844: copy-to-clipboard / OSC 52 path - prAssigneeList in view.go

## Question
Can content rendered by `prAssigneeList` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L402) write to the victim's clipboard via OSC 52, staging a command for the next paste?

## Target
- File/function: [pkg/cmd/pr/view/view.go:402](pkg/cmd/pr/view/view.go#L402) - `prAssigneeList`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a body containing an OSC 52 payload.
- Invariant to test: OSC sequences are stripped from all remote text.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting OSC 52 bytes never appear in output.
