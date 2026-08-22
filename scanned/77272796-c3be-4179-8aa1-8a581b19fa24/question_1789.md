# Q1789: registry response controls the download URL - promptForSkillOrigin in update.go

## Question
Can the registry/search response consumed by `promptForSkillOrigin` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L643) point the download at an arbitrary host or path?

## Target
- File/function: [pkg/cmd/skills/update/update.go:643](pkg/cmd/skills/update/update.go#L643) - `promptForSkillOrigin`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a registry entry whose URL field targets the attacker's server.
- Invariant to test: Download URLs are host-validated against the authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with a hostile URL field asserting rejection.
