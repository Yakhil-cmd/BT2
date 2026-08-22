# Q4523: symlink not resolved before write - (Manager).cleanExtensionUpdateDir in manager.go

## Question
Does `cleanExtensionUpdateDir` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L877) write through a path component that may already be a symlink created earlier by the same attacker-controlled payload?

## Target
- File/function: [pkg/cmd/extension/manager.go:877](pkg/cmd/extension/manager.go#L877) - `(Manager).cleanExtensionUpdateDir`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Have the payload create `dir -> /home/victim/.ssh` first, then a file under `dir/`.
- Invariant to test: Writes resolve symlinks and reject any component leaving the root (O_NOFOLLOW semantics).
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Integration test extracting a two-entry payload (symlink then file) and asserting the outside target is untouched.
