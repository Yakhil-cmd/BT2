# Q1912: partial write left on failure - runDownload in download.go

## Question
If the transfer in `runDownload` in [pkg/cmd/run/download/download.go](pkg/cmd/run/download/download.go#L109) fails or is truncated, is a partial file left where a later step (or the user) treats it as complete and verified?

## Target
- File/function: [pkg/cmd/run/download/download.go:109](pkg/cmd/run/download/download.go#L109) - `runDownload`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Cut the connection mid-download from an attacker-influenced endpoint.
- Invariant to test: Downloads write to a temp file and are renamed only after full, verified receipt.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test truncating the body asserting no final file exists.
