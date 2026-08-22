# Q5342: TOCTOU between validation and write - printFileTree in install.go

## Question
Is there a window in `printFileTree` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1151) between validating the destination and creating it, during which the same attacker payload can turn that destination into a link?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1151](pkg/cmd/skills/install/install.go#L1151) - `printFileTree`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Interleave payload entries so validation sees a regular path and the write sees a link.
- Invariant to test: Validation and creation act on the same file handle, not on a re-resolved path.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Concurrency test asserting the write uses openat-style handles or re-validates atomically.
