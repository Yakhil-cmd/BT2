# Q1915: partial write left on failure - ListArtifacts in artifacts.go

## Question
If the transfer in `ListArtifacts` in [pkg/cmd/run/shared/artifacts.go](pkg/cmd/run/shared/artifacts.go#L23) fails or is truncated, is a partial file left where a later step (or the user) treats it as complete and verified?

## Target
- File/function: [pkg/cmd/run/shared/artifacts.go:23](pkg/cmd/run/shared/artifacts.go#L23) - `ListArtifacts`
- Entrypoint: gh run
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Cut the connection mid-download from an attacker-influenced endpoint.
- Invariant to test: Downloads write to a temp file and are renamed only after full, verified receipt.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test truncating the body asserting no final file exists.
