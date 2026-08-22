# Q4054: temporary directory predictable - runDownload in download.go

## Question
Does `runDownload` in [pkg/cmd/run/download/download.go](pkg/cmd/run/download/download.go#L109) stage downloads in a predictable shared temp path where another local process can substitute the content before it is used or verified?

## Target
- File/function: [pkg/cmd/run/download/download.go:109](pkg/cmd/run/download/download.go#L109) - `runDownload`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Pre-create the predictable path before the victim runs gh run download.
- Invariant to test: Staging uses a per-run private directory created with exclusive semantics.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a random, 0700 staging directory.
