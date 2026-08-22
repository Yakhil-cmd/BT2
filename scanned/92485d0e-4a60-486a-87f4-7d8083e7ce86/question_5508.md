# Q5508: markdown renderer emits raw escapes - NewCmdEdit in edit.go

## Question
Does the markdown/HTML path in `NewCmdEdit` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L45) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:45](pkg/cmd/gist/edit/edit.go#L45) - `NewCmdEdit`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh gist edit.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
