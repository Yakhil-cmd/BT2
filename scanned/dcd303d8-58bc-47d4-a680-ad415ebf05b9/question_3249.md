# Q3249: skill files escape the skills directory - stripGitHubMetadata in publish.go

## Question
Can the file names inside a published skill drive `stripGitHubMetadata` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L1143) to write outside the per-skill directory (traversal, absolute path, symlink, long-path/UNC on Windows)?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:1143](pkg/cmd/skills/publish/publish.go#L1143) - `stripGitHubMetadata`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose entry is `../../.config/gh/hosts.yml`.
- Invariant to test: Every skill file resolves inside its own directory.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile entry names asserting confinement.
