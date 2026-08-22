# Q2645: partial write left on failure - NewCmdReadDir in read_dir.go

## Question
If the transfer in `NewCmdReadDir` in [pkg/cmd/repo/read-dir/read_dir.go](pkg/cmd/repo/read-dir/read_dir.go#L44) fails or is truncated, is a partial file left where a later step (or the user) treats it as complete and verified?

## Target
- File/function: [pkg/cmd/repo/read-dir/read_dir.go:44](pkg/cmd/repo/read-dir/read_dir.go#L44) - `NewCmdReadDir`
- Entrypoint: gh repo read-dir
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Cut the connection mid-download from an attacker-influenced endpoint.
- Invariant to test: Downloads write to a temp file and are renamed only after full, verified receipt.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test truncating the body asserting no final file exists.
