# Q2008: hyperlink target unvalidated - addRow in output.go

## Question
Does `addRow` in [pkg/cmd/pr/checks/output.go](pkg/cmd/pr/checks/output.go#L11) emit OSC 8 hyperlinks whose target comes from remote data, letting the attacker point a clickable link at a non-http URI?

## Target
- File/function: [pkg/cmd/pr/checks/output.go:11](pkg/cmd/pr/checks/output.go#L11) - `addRow`
- Entrypoint: gh pr checks
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object whose URL field becomes the link target.
- Invariant to test: Hyperlink targets are scheme- and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting only http(s) targets are emitted.
