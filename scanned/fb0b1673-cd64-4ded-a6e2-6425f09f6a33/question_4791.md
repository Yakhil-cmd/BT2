# Q4791: missing timeout enables hang - GistIDFromURL in shared.go

## Question
Does the request path in `GistIDFromURL` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L84) run without a timeout/context deadline so an attacker-controlled endpoint can hang the victim's gh indefinitely (including in CI)?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:84](pkg/cmd/gist/shared/shared.go#L84) - `GistIDFromURL`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve a slow-loris response from the host the victim's gh talks to.
- Invariant to test: Every outbound request carries a bounded timeout.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a stalling server asserting the call returns within the deadline.
