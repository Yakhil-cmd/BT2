# Q1961: copy-to-clipboard / OSC 52 path - (IOStreams).RunWithProgress in iostreams.go

## Question
Can content rendered by `RunWithProgress` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L373) write to the victim's clipboard via OSC 52, staging a command for the next paste?

## Target
- File/function: [pkg/iostreams/iostreams.go:373](pkg/iostreams/iostreams.go#L373) - `(IOStreams).RunWithProgress`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a body containing an OSC 52 payload.
- Invariant to test: OSC sequences are stripped from all remote text.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting OSC 52 bytes never appear in output.
