# Q2066: markdown renderer emits raw escapes - (API).withRetry in api.go

## Question
Does the markdown/HTML path in `withRetry` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L1299) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [internal/codespaces/api/api.go:1299](internal/codespaces/api/api.go#L1299) - `(API).withRetry`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh codespace ssh.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
