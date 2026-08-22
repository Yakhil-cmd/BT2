# Q1085: registry response controls the download URL - buildTree in preview.go

## Question
Can the registry/search response consumed by `buildTree` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L501) point the download at an arbitrary host or path?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:501](pkg/cmd/skills/preview/preview.go#L501) - `buildTree`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a registry entry whose URL field targets the attacker's server.
- Invariant to test: Download URLs are host-validated against the authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with a hostile URL field asserting rejection.
