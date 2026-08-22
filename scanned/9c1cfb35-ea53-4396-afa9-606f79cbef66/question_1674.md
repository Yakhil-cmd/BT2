# Q1674: TOCTOU between validation and write - (Extension).IsPinned in extension.go

## Question
Is there a window in `IsPinned` in [pkg/cmd/extension/extension.go](pkg/cmd/extension/extension.go#L150) between validating the destination and creating it, during which the same attacker payload can turn that destination into a link?

## Target
- File/function: [pkg/cmd/extension/extension.go:150](pkg/cmd/extension/extension.go#L150) - `(Extension).IsPinned`
- Entrypoint: gh extension extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Interleave payload entries so validation sees a regular path and the write sees a link.
- Invariant to test: Validation and creation act on the same file handle, not on a re-resolved path.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test asserting the write uses openat-style handles or re-validates atomically.
