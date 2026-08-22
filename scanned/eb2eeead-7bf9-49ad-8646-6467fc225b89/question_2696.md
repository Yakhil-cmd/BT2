# Q2696: hyperlink target unvalidated - NewWithWriter in table_printer.go

## Question
Does `NewWithWriter` in [internal/tableprinter/table_printer.go](internal/tableprinter/table_printer.go#L58) emit OSC 8 hyperlinks whose target comes from remote data, letting the attacker point a clickable link at a non-http URI?

## Target
- File/function: [internal/tableprinter/table_printer.go:58](internal/tableprinter/table_printer.go#L58) - `NewWithWriter`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object whose URL field becomes the link target.
- Invariant to test: Hyperlink targets are scheme- and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting only http(s) targets are emitted.
