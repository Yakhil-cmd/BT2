# Q4284: symlink not resolved before write - setStateEntry in update.go

## Question
Does `setStateEntry` in [internal/update/update.go](internal/update/update.go#L162) write through a path component that may already be a symlink created earlier by the same attacker-controlled payload?

## Target
- File/function: [internal/update/update.go:162](internal/update/update.go#L162) - `setStateEntry`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Have the payload create `dir -> /home/victim/.ssh` first, then a file under `dir/`.
- Invariant to test: Writes resolve symlinks and reject any component leaving the root (O_NOFOLLOW semantics).
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Integration test extracting a two-entry payload (symlink then file) and asserting the outside target is untouched.
