# Q4810: truncation hides the security-relevant part - (IOStreams).IsStdoutTTY in iostreams.go

## Question
Does `IsStdoutTTY` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L181) truncate or column-fit remote text such that a host, URL, or repo name shown for a trust decision is cut, letting a lookalike be mistaken for the real one?

## Target
- File/function: [pkg/iostreams/iostreams.go:181](pkg/iostreams/iostreams.go#L181) - `(IOStreams).IsStdoutTTY`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Use a very long owner/host prefix so the visible portion reads as github.com.
- Invariant to test: Security-relevant identifiers are never elided; they are shown in full or the action aborts.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test with a long hostile name asserting the full identifier appears.
