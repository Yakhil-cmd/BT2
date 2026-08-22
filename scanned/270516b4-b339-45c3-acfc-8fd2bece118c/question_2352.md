# Q2352: markdown renderer emits raw escapes - developRunList in develop.go

## Question
Does the markdown/HTML path in `developRunList` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L319) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:319](pkg/cmd/issue/develop/develop.go#L319) - `developRunList`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh issue develop.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
