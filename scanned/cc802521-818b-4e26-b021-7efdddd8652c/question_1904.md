# Q1904: partial write left on failure - checkArchiveTypeOption in download.go

## Question
If the transfer in `checkArchiveTypeOption` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L123) fails or is truncated, is a partial file left where a later step (or the user) treats it as complete and verified?

## Target
- File/function: [pkg/cmd/release/download/download.go:123](pkg/cmd/release/download/download.go#L123) - `checkArchiveTypeOption`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Cut the connection mid-download from an attacker-influenced endpoint.
- Invariant to test: Downloads write to a temp file and are renamed only after full, verified receipt.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test truncating the body asserting no final file exists.
