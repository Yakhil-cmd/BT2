# Q4993: path traversal in join - CheckForExtensionUpdate in update.go

## Question
Can an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes reaching `CheckForExtensionUpdate` in [internal/update/update.go](internal/update/update.go#L51) contain `../` or an absolute path so the `filepath.Join` target escapes the intended output directory?

## Target
- File/function: [internal/update/update.go:51](internal/update/update.go#L51) - `CheckForExtensionUpdate`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish an entry named `../../.bashrc` (or `..\..\` on Windows) and let the victim run gh alias import.
- Invariant to test: Every written path must remain inside the chosen root after Clean and Abs.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Fuzz the name with traversal, absolute, drive-letter, and UNC forms; assert the resolved path is prefixed by the root.
