# Q3621: markdown renderer emits raw escapes - logoutRun in logout.go

## Question
Does the markdown/HTML path in `logoutRun` in [pkg/cmd/auth/logout/logout.go](pkg/cmd/auth/logout/logout.go#L79) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/auth/logout/logout.go:79](pkg/cmd/auth/logout/logout.go#L79) - `logoutRun`
- Entrypoint: gh auth logout
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh auth logout.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
