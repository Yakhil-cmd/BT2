# Q3856: registry response controls the download URL - installLocalSkill in installer.go

## Question
Can the registry/search response consumed by `installLocalSkill` in [internal/skills/installer/installer.go](internal/skills/installer/installer.go#L180) point the download at an arbitrary host or path?

## Target
- File/function: [internal/skills/installer/installer.go:180](internal/skills/installer/installer.go#L180) - `installLocalSkill`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a registry entry whose URL field targets the attacker's server.
- Invariant to test: Download URLs are host-validated against the authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with a hostile URL field asserting rejection.
