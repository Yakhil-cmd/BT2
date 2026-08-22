# Q5567: markdown renderer emits raw escapes - PrintHeader in display.go

## Question
Does the markdown/HTML path in `PrintHeader` in [pkg/cmd/pr/shared/display.go](pkg/cmd/pr/shared/display.go#L58) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/pr/shared/display.go:58](pkg/cmd/pr/shared/display.go#L58) - `PrintHeader`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh pr.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
