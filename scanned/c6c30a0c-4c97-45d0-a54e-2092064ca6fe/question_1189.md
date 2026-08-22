# Q1189: temporary directory predictable - NewCmdDownload in download.go

## Question
Does `NewCmdDownload` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L46) stage downloads in a predictable shared temp path where another local process can substitute the content before it is used or verified?

## Target
- File/function: [pkg/cmd/release/download/download.go:46](pkg/cmd/release/download/download.go#L46) - `NewCmdDownload`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Pre-create the predictable path before the victim runs gh release download.
- Invariant to test: Staging uses a per-run private directory created with exclusive semantics.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a random, 0700 staging directory.
