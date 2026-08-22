# Q5960: registry response controls the download URL - matchSelectedSkills in install.go

## Question
Can the registry/search response consumed by `matchSelectedSkills` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L885) point the download at an arbitrary host or path?

## Target
- File/function: [pkg/cmd/skills/install/install.go:885](pkg/cmd/skills/install/install.go#L885) - `matchSelectedSkills`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a registry entry whose URL field targets the attacker's server.
- Invariant to test: Download URLs are host-validated against the authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with a hostile URL field asserting rejection.
