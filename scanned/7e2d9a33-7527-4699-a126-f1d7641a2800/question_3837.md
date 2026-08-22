# Q3837: markdown renderer emits raw escapes - NewCmdExtension in extension.go

## Question
Does the markdown/HTML path in `NewCmdExtension` in [pkg/cmd/root/extension.go](pkg/cmd/root/extension.go#L22) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/root/extension.go:22](pkg/cmd/root/extension.go#L22) - `NewCmdExtension`
- Entrypoint: gh root extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh root extension.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
