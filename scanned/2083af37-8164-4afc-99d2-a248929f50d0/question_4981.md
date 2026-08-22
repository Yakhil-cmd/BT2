# Q4981: markdown renderer emits raw escapes - setRun in set.go

## Question
Does the markdown/HTML path in `setRun` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L203) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/secret/set/set.go:203](pkg/cmd/secret/set/set.go#L203) - `setRun`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh secret set.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
