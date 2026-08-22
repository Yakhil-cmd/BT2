# Q0537: symlink not resolved before write - (IOStreams).TempFile in iostreams.go

## Question
Does `TempFile` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L459) write through a path component that may already be a symlink created earlier by the same attacker-controlled payload?

## Target
- File/function: [pkg/iostreams/iostreams.go:459](pkg/iostreams/iostreams.go#L459) - `(IOStreams).TempFile`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Have the payload create `dir -> /home/victim/.ssh` first, then a file under `dir/`.
- Invariant to test: Writes resolve symlinks and reject any component leaving the root (O_NOFOLLOW semantics).
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Integration test extracting a two-entry payload (symlink then file) and asserting the outside target is untouched.
