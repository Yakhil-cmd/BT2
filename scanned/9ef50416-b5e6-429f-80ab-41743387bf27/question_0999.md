# Q0999: registry response controls the download URL - InstallLocal in installer.go

## Question
Can the registry/search response consumed by `InstallLocal` in [internal/skills/installer/installer.go](internal/skills/installer/installer.go#L156) point the download at an arbitrary host or path?

## Target
- File/function: [internal/skills/installer/installer.go:156](internal/skills/installer/installer.go#L156) - `InstallLocal`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a registry entry whose URL field targets the attacker's server.
- Invariant to test: Download URLs are host-validated against the authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with a hostile URL field asserting rejection.
