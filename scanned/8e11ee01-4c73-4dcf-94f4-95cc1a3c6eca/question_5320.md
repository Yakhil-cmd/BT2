# Q5320: deletion of attacker-chosen path - DiscoverLocalSkillsWithOptions in discovery.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata steer the cleanup/RemoveAll in `DiscoverLocalSkillsWithOptions` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L974) at a path outside the directory gh created?

## Target
- File/function: [internal/skills/discovery/discovery.go:974](internal/skills/discovery/discovery.go#L974) - `DiscoverLocalSkillsWithOptions`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a name that resolves outside the install/download root so the cleanup deletes victim data.
- Invariant to test: Removal targets only paths gh itself created inside its own root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the removal path is validated with the same root check as writes.
