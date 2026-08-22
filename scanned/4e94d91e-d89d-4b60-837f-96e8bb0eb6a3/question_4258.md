# Q4258: unbounded io.Copy of remote body - extractTarGz in copilot.go

## Question
Does `extractTarGz` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L413) io.Copy an attacker-sized HTTP body or archive stream into memory or disk without a limit?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:413](pkg/cmd/copilot/copilot.go#L413) - `extractTarGz`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Serve a response with no Content-Length and an endless body from a host the victim points gh at.
- Invariant to test: All remote reads are bounded by an explicit limit reader.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an infinite reader asserting the call returns an error after the cap.
