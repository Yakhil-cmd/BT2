# Q4639: symlink not resolved before write - swapDirectoryContents in update.go

## Question
Does `swapDirectoryContents` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L470) write through a path component that may already be a symlink created earlier by the same attacker-controlled payload?

## Target
- File/function: [pkg/cmd/skills/update/update.go:470](pkg/cmd/skills/update/update.go#L470) - `swapDirectoryContents`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Have the payload create `dir -> /home/victim/.ssh` first, then a file under `dir/`.
- Invariant to test: Writes resolve symlinks and reject any component leaving the root (O_NOFOLLOW semantics).
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Integration test extracting a two-entry payload (symlink then file) and asserting the outside target is untouched.
