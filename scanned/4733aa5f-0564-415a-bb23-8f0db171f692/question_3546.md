# Q3546: TOCTOU between validation and write - removeCopilot in copilot.go

## Question
Is there a window in `removeCopilot` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L470) between validating the destination and creating it, during which the same attacker payload can turn that destination into a link?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:470](pkg/cmd/copilot/copilot.go#L470) - `removeCopilot`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Interleave payload entries so validation sees a regular path and the write sees a link.
- Invariant to test: Validation and creation act on the same file handle, not on a re-resolved path.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test asserting the write uses openat-style handles or re-validates atomically.
