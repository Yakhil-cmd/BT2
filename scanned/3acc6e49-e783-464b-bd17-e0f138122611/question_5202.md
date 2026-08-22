# Q5202: symlink not resolved before write - NewCmdDevelop in develop.go

## Question
Does `NewCmdDevelop` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L40) write through a path component that may already be a symlink created earlier by the same attacker-controlled payload?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:40](pkg/cmd/issue/develop/develop.go#L40) - `NewCmdDevelop`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Have the payload create `dir -> /home/victim/.ssh` first, then a file under `dir/`.
- Invariant to test: Writes resolve symlinks and reject any component leaving the root (O_NOFOLLOW semantics).
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Integration test extracting a two-entry payload (symlink then file) and asserting the outside target is untouched.
