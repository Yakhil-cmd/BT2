# Q3956: existing file clobbered - checkInstalledSkillDirs in publish.go

## Question
Does `checkInstalledSkillDirs` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L905) overwrite an existing file (no O_EXCL / no collision check) when the name comes from a published skill's archive entries, frontmatter, and registry metadata, allowing gh's own config, hosts file, or an installed binary to be replaced?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:905](pkg/cmd/skills/publish/publish.go#L905) - `checkInstalledSkillDirs`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Name the remote object exactly like a gh-managed file so the write lands on it.
- Invariant to test: Files created from remote content are never allowed to replace pre-existing paths.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test pre-creating the target and asserting the operation errors instead of truncating.
