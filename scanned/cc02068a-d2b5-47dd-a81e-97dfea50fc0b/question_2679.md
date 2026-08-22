# Q2679: TOCTOU between validation and write - (IOStreams).TempFile in iostreams.go

## Question
Is there a window in `TempFile` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L459) between validating the destination and creating it, during which the same attacker payload can turn that destination into a link?

## Target
- File/function: [pkg/iostreams/iostreams.go:459](pkg/iostreams/iostreams.go#L459) - `(IOStreams).TempFile`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Interleave payload entries so validation sees a regular path and the write sees a link.
- Invariant to test: Validation and creation act on the same file handle, not on a re-resolved path.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test asserting the write uses openat-style handles or re-validates atomically.
