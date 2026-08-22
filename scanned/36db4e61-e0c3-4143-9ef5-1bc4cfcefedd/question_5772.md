# Q5772: markdown renderer emits raw escapes - newGitClient in default.go

## Question
Does the markdown/HTML path in `newGitClient` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L240) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/factory/default.go:240](pkg/cmd/factory/default.go#L240) - `newGitClient`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh factory default.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
