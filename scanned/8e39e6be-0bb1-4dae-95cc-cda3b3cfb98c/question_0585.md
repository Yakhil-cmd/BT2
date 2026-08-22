# Q0585: hyperlink target unvalidated - parseSection in browse.go

## Question
Does `parseSection` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L230) emit OSC 8 hyperlinks whose target comes from remote data, letting the attacker point a clickable link at a non-http URI?

## Target
- File/function: [pkg/cmd/browse/browse.go:230](pkg/cmd/browse/browse.go#L230) - `parseSection`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object whose URL field becomes the link target.
- Invariant to test: Hyperlink targets are scheme- and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting only http(s) targets are emitted.
