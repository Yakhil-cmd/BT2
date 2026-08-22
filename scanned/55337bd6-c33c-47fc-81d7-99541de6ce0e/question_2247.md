# Q2247: TOCTOU between validation and write - ParseAbsolute in absolute.go

## Question
Is there a window in `ParseAbsolute` in [internal/safepaths/absolute.go](internal/safepaths/absolute.go#L17) between validating the destination and creating it, during which the same attacker payload can turn that destination into a link?

## Target
- File/function: [internal/safepaths/absolute.go:17](internal/safepaths/absolute.go#L17) - `ParseAbsolute`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Interleave payload entries so validation sees a regular path and the write sees a link.
- Invariant to test: Validation and creation act on the same file handle, not on a re-resolved path.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test asserting the write uses openat-style handles or re-validates atomically.
