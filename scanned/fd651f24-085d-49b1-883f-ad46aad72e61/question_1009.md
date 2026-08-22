# Q1009: path traversal in join - lockfilePath in lockfile.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata reaching `lockfilePath` in [internal/skills/lockfile/lockfile.go](internal/skills/lockfile/lockfile.go#L43) contain `../` or an absolute path so the `filepath.Join` target escapes the intended output directory?

## Target
- File/function: [internal/skills/lockfile/lockfile.go:43](internal/skills/lockfile/lockfile.go#L43) - `lockfilePath`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an entry named `../../.bashrc` (or `..\..\` on Windows) and let the victim run gh skills install.
- Invariant to test: Every written path must remain inside the chosen root after Clean and Abs.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Fuzz the name with traversal, absolute, drive-letter, and UNC forms; assert the resolved path is prefixed by the root.
