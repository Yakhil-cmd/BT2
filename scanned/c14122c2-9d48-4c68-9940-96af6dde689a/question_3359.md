# Q3359: output directory itself attacker-influenced - NewCmdReadDir in read_dir.go

## Question
Can the destination directory used by `NewCmdReadDir` in [pkg/cmd/repo/read-dir/read_dir.go](pkg/cmd/repo/read-dir/read_dir.go#L44) be derived from remote data (run name, artifact name, repo name) rather than from user input?

## Target
- File/function: [pkg/cmd/repo/read-dir/read_dir.go:44](pkg/cmd/repo/read-dir/read_dir.go#L44) - `NewCmdReadDir`
- Entrypoint: gh repo read-dir
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object whose name becomes the directory and escapes.
- Invariant to test: The destination root comes from the user; remote names contribute only sanitized leaf elements.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the destination root is unchanged by hostile names.
