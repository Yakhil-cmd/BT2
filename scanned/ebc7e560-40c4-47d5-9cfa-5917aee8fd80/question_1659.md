# Q1659: TOCTOU between validation and write - (Manager).UpdateDir in manager.go

## Question
Is there a window in `UpdateDir` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L598) between validating the destination and creating it, during which the same attacker payload can turn that destination into a link?

## Target
- File/function: [pkg/cmd/extension/manager.go:598](pkg/cmd/extension/manager.go#L598) - `(Manager).UpdateDir`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Interleave payload entries so validation sees a regular path and the write sees a link.
- Invariant to test: Validation and creation act on the same file handle, not on a re-resolved path.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test asserting the write uses openat-style handles or re-validates atomically.
