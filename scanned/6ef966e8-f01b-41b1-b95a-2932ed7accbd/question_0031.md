# Q0031: TOCTOU between validation and write - HomeDirPath in config.go

## Question
Is there a window in `HomeDirPath` in [internal/config/config.go](internal/config/config.go#L702) between validating the destination and creating it, during which the same attacker payload can turn that destination into a link?

## Target
- File/function: [internal/config/config.go:702](internal/config/config.go#L702) - `HomeDirPath`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Interleave payload entries so validation sees a regular path and the write sees a link.
- Invariant to test: Validation and creation act on the same file handle, not on a re-resolved path.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test asserting the write uses openat-style handles or re-validates atomically.
