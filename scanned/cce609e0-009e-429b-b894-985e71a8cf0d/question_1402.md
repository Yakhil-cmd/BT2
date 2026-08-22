# Q1402: decompression bomb - extractTarGz in copilot.go

## Question
Is the extraction in `extractTarGz` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L413) unbounded in total size, entry count, or per-entry size, so a small attacker-published archive exhausts the victim's disk or memory?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:413](pkg/cmd/copilot/copilot.go#L413) - `extractTarGz`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a highly compressible artifact/skill archive and let the victim download it.
- Invariant to test: Extraction enforces a total-bytes and entry-count limit with a bounded io.CopyN.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test extracting a bomb fixture with a size cap and assert the operation aborts.
