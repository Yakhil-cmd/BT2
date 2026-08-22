# Q1028: skill files escape the skills directory - DiscoverSkills in discovery.go

## Question
Can the file names inside a published skill drive `DiscoverSkills` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L550) to write outside the per-skill directory (traversal, absolute path, symlink, long-path/UNC on Windows)?

## Target
- File/function: [internal/skills/discovery/discovery.go:550](internal/skills/discovery/discovery.go#L550) - `DiscoverSkills`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose entry is `../../.config/gh/hosts.yml`.
- Invariant to test: Every skill file resolves inside its own directory.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile entry names asserting confinement.
