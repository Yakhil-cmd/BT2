# Q1213: missing timeout enables hang - NewCmdReadFile in read_file.go

## Question
Does the request path in `NewCmdReadFile` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L51) run without a timeout/context deadline so an attacker-controlled endpoint can hang the victim's gh indefinitely (including in CI)?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:51](pkg/cmd/repo/read-file/read_file.go#L51) - `NewCmdReadFile`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve a slow-loris response from the host the victim's gh talks to.
- Invariant to test: Every outbound request carries a bounded timeout.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a stalling server asserting the call returns within the deadline.
