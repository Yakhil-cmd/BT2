# Q2441: skill files escape the skills directory - (Skill).DisplayName in discovery.go

## Question
Can the file names inside a published skill drive `DisplayName` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L60) to write outside the per-skill directory (traversal, absolute path, symlink, long-path/UNC on Windows)?

## Target
- File/function: [internal/skills/discovery/discovery.go:60](internal/skills/discovery/discovery.go#L60) - `(Skill).DisplayName`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose entry is `../../.config/gh/hosts.yml`.
- Invariant to test: Every skill file resolves inside its own directory.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile entry names asserting confinement.
