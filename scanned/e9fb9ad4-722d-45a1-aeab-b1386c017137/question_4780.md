# Q4780: temporary directory predictable - ExtractZip in zip.go

## Question
Does `ExtractZip` in [internal/zip/zip.go](internal/zip/zip.go#L24) stage downloads in a predictable shared temp path where another local process can substitute the content before it is used or verified?

## Target
- File/function: [internal/zip/zip.go:24](internal/zip/zip.go#L24) - `ExtractZip`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Pre-create the predictable path before the victim runs gh run download.
- Invariant to test: Staging uses a per-run private directory created with exclusive semantics.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting a random, 0700 staging directory.
