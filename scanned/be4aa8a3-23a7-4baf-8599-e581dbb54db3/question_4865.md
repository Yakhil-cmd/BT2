# Q4865: markdown renderer emits raw escapes - printTable in output.go

## Question
Does the markdown/HTML path in `printTable` in [pkg/cmd/pr/checks/output.go](pkg/cmd/pr/checks/output.go#L94) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/pr/checks/output.go:94](pkg/cmd/pr/checks/output.go#L94) - `printTable`
- Entrypoint: gh pr checks
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh pr checks.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
