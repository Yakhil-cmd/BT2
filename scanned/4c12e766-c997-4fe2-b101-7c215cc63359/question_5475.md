# Q5475: missing timeout enables hang - downloadAsset in download.go

## Question
Does the request path in `downloadAsset` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L300) run without a timeout/context deadline so an attacker-controlled endpoint can hang the victim's gh indefinitely (including in CI)?

## Target
- File/function: [pkg/cmd/release/download/download.go:300](pkg/cmd/release/download/download.go#L300) - `downloadAsset`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve a slow-loris response from the host the victim's gh talks to.
- Invariant to test: Every outbound request carries a bounded timeout.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a stalling server asserting the call returns within the deadline.
