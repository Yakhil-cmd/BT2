# Q4514: path traversal in join - (Manager).UpdateDir in manager.go

## Question
Can an extension repository, its release assets, and its manifest fields reaching `UpdateDir` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L598) contain `../` or an absolute path so the `filepath.Join` target escapes the intended output directory?

## Target
- File/function: [pkg/cmd/extension/manager.go:598](pkg/cmd/extension/manager.go#L598) - `(Manager).UpdateDir`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an entry named `../../.bashrc` (or `..\..\` on Windows) and let the victim run gh extension manager.
- Invariant to test: Every written path must remain inside the chosen root after Clean and Abs.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Fuzz the name with traversal, absolute, drive-letter, and UNC forms; assert the resolved path is prefixed by the root.
