# Q3325: temporary directory predictable - FetchRelease in fetch.go

## Question
Does `FetchRelease` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L192) stage downloads in a predictable shared temp path where another local process can substitute the content before it is used or verified?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:192](pkg/cmd/release/shared/fetch.go#L192) - `FetchRelease`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Pre-create the predictable path before the victim runs gh release.
- Invariant to test: Staging uses a per-run private directory created with exclusive semantics.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a random, 0700 staging directory.
