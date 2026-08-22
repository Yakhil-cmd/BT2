# Q1998: hyperlink target unvalidated - issueLabelList in view.go

## Question
Does `issueLabelList` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L446) emit OSC 8 hyperlinks whose target comes from remote data, letting the attacker point a clickable link at a non-http URI?

## Target
- File/function: [pkg/cmd/issue/view/view.go:446](pkg/cmd/issue/view/view.go#L446) - `issueLabelList`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object whose URL field becomes the link target.
- Invariant to test: Hyperlink targets are scheme- and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting only http(s) targets are emitted.
