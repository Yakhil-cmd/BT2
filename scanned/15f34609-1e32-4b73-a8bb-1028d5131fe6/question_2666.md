# Q2666: markdown renderer emits raw escapes - NewUntrustedBytes in untrusted.go

## Question
Does the markdown/HTML path in `NewUntrustedBytes` in [pkg/iostreams/untrusted.go](pkg/iostreams/untrusted.go#L31) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/iostreams/untrusted.go:31](pkg/iostreams/untrusted.go#L31) - `NewUntrustedBytes`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh pr view.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
