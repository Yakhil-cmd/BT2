# Q4990: TOCTOU between validation and write - (Context).LocalPublicKeys in ssh_keys.go

## Question
Is there a window in `LocalPublicKeys` in [pkg/ssh/ssh_keys.go](pkg/ssh/ssh_keys.go#L37) between validating the destination and creating it, during which the same attacker payload can turn that destination into a link?

## Target
- File/function: [pkg/ssh/ssh_keys.go:37](pkg/ssh/ssh_keys.go#L37) - `(Context).LocalPublicKeys`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Interleave payload entries so validation sees a regular path and the write sees a link.
- Invariant to test: Validation and creation act on the same file handle, not on a re-resolved path.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test asserting the write uses openat-style handles or re-validates atomically.
