# Q2106: markdown renderer emits raw escapes - followLogs in create.go

## Question
Does the markdown/HTML path in `followLogs` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L263) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:263](pkg/cmd/agent-task/create/create.go#L263) - `followLogs`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh agent task create.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
