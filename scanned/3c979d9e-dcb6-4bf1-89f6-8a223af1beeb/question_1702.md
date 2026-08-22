# Q1702: markdown renderer emits raw escapes - printError in cmd.go

## Question
Does the markdown/HTML path in `printError` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L282) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [internal/ghcmd/cmd.go:282](internal/ghcmd/cmd.go#L282) - `printError`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh extension install.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
