# Q2887: path traversal in join - HomeDirPath in config.go

## Question
Can a hostname, OAuth/device response, or git credential-protocol input the attacker supplies reaching `HomeDirPath` in [internal/config/config.go](internal/config/config.go#L702) contain `../` or an absolute path so the `filepath.Join` target escapes the intended output directory?

## Target
- File/function: [internal/config/config.go:702](internal/config/config.go#L702) - `HomeDirPath`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish an entry named `../../.bashrc` (or `..\..\` on Windows) and let the victim run gh auth login.
- Invariant to test: Every written path must remain inside the chosen root after Clean and Abs.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Fuzz the name with traversal, absolute, drive-letter, and UNC forms; assert the resolved path is prefixed by the root.
