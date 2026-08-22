# Q0127: markdown renderer emits raw escapes - printHeaders in api.go

## Question
Does the markdown/HTML path in `printHeaders` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L613) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/api/api.go:613](pkg/cmd/api/api.go#L613) - `printHeaders`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh api.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
