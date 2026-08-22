# Q5473: decompression bomb - downloadRun in download.go

## Question
Is the extraction in `downloadRun` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L142) unbounded in total size, entry count, or per-entry size, so a small attacker-published archive exhausts the victim's disk or memory?

## Target
- File/function: [pkg/cmd/release/download/download.go:142](pkg/cmd/release/download/download.go#L142) - `downloadRun`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a highly compressible artifact/skill archive and let the victim download it.
- Invariant to test: Extraction enforces a total-bytes and entry-count limit with a bounded io.CopyN.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test extracting a bomb fixture with a size cap and assert the operation aborts.
