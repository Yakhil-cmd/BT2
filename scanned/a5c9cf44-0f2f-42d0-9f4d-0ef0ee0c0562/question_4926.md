# Q4926: path traversal in join - checkAndUpdateOldKeyPair in ssh.go

## Question
Can codespace/API response fields and everything the codespace-side process sends back reaching `checkAndUpdateOldKeyPair` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L426) contain `../` or an absolute path so the `filepath.Join` target escapes the intended output directory?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:426](pkg/cmd/codespace/ssh.go#L426) - `checkAndUpdateOldKeyPair`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish an entry named `../../.bashrc` (or `..\..\` on Windows) and let the victim run gh codespace ssh.
- Invariant to test: Every written path must remain inside the chosen root after Clean and Abs.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Fuzz the name with traversal, absolute, drive-letter, and UNC forms; assert the resolved path is prefixed by the root.
