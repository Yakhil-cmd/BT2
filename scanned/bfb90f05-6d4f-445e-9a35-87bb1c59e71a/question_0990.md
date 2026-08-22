# Q0990: path traversal in join - checkForUpdate in cmd.go

## Question
Can an extension repository, its release assets, and its manifest fields reaching `checkForUpdate` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L318) contain `../` or an absolute path so the `filepath.Join` target escapes the intended output directory?

## Target
- File/function: [internal/ghcmd/cmd.go:318](internal/ghcmd/cmd.go#L318) - `checkForUpdate`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an entry named `../../.bashrc` (or `..\..\` on Windows) and let the victim run gh extension install.
- Invariant to test: Every written path must remain inside the chosen root after Clean and Abs.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Fuzz the name with traversal, absolute, drive-letter, and UNC forms; assert the resolved path is prefixed by the root.
