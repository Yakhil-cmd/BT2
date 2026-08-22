# Q5309: registry response controls the download URL - matchHiddenDirConventions in discovery.go

## Question
Can the registry/search response consumed by `matchHiddenDirConventions` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L504) point the download at an arbitrary host or path?

## Target
- File/function: [internal/skills/discovery/discovery.go:504](internal/skills/discovery/discovery.go#L504) - `matchHiddenDirConventions`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a registry entry whose URL field targets the attacker's server.
- Invariant to test: Download URLs are host-validated against the authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with a hostile URL field asserting rejection.
