# Q1100: ref name starting with a dash - checkInstalledSkillDirs in publish.go

## Question
Does `checkInstalledSkillDirs` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L905) place a branch/ref/tag name from remote data in a git argv position where a leading `-` becomes an option (e.g. `--upload-pack=`)?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:905](pkg/cmd/skills/publish/publish.go#L905) - `checkInstalledSkillDirs`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a PR branch or tag named `--upload-pack=touch /tmp/pwn`.
- Invariant to test: Ref values are validated against git's ref format and always follow `--`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test with hostile ref names asserting rejection or correct positioning.
