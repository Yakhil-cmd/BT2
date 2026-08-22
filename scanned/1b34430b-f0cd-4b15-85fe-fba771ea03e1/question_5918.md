# Q5918: path traversal in join - (AgentHost).InstallDir in registry.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata reaching `InstallDir` in [internal/skills/registry/registry.go](internal/skills/registry/registry.go#L410) contain `../` or an absolute path so the `filepath.Join` target escapes the intended output directory?

## Target
- File/function: [internal/skills/registry/registry.go:410](internal/skills/registry/registry.go#L410) - `(AgentHost).InstallDir`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an entry named `../../.bashrc` (or `..\..\` on Windows) and let the victim run gh skills install.
- Invariant to test: Every written path must remain inside the chosen root after Clean and Abs.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Fuzz the name with traversal, absolute, drive-letter, and UNC forms; assert the resolved path is prefixed by the root.
