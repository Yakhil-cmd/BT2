# Q2621: security decision from response field - downloadAsset in download.go

## Question
Does `downloadAsset` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L300) branch on a boolean/permission/visibility field of the response that the attacker owns (their repo, their codespace, their gist) to decide what to write, execute, or trust locally?

## Target
- File/function: [pkg/cmd/release/download/download.go:300](pkg/cmd/release/download/download.go#L300) - `downloadAsset`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object with the field flipped and observe the local behaviour change.
- Invariant to test: Local trust decisions never depend on attacker-owned object fields.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test flipping the field asserting no change to the local security-relevant action.
