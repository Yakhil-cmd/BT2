# Q0178: markdown renderer emits raw escapes - syncRemoteRepo in sync.go

## Question
Does the markdown/HTML path in `syncRemoteRepo` in [pkg/cmd/repo/sync/sync.go](pkg/cmd/repo/sync/sync.go#L168) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/repo/sync/sync.go:168](pkg/cmd/repo/sync/sync.go#L168) - `syncRemoteRepo`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh repo sync.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
