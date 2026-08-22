# Q5635: markdown renderer emits raw escapes - newSSHCmd in ssh.go

## Question
Does the markdown/HTML path in `newSSHCmd` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L49) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:49](pkg/cmd/codespace/ssh.go#L49) - `newSSHCmd`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh codespace ssh.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
