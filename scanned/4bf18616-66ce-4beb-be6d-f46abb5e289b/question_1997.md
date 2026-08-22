# Q1997: copy-to-clipboard / OSC 52 path - issueProjectList in view.go

## Question
Can content rendered by `issueProjectList` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L412) write to the victim's clipboard via OSC 52, staging a command for the next paste?

## Target
- File/function: [pkg/cmd/issue/view/view.go:412](pkg/cmd/issue/view/view.go#L412) - `issueProjectList`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a body containing an OSC 52 payload.
- Invariant to test: OSC sequences are stripped from all remote text.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting OSC 52 bytes never appear in output.
