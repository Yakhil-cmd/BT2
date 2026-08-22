# Q1807: registry response controls the download URL - detectDefaultBranch in publish.go

## Question
Can the registry/search response consumed by `detectDefaultBranch` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L690) point the download at an arbitrary host or path?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:690](pkg/cmd/skills/publish/publish.go#L690) - `detectDefaultBranch`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a registry entry whose URL field targets the attacker's server.
- Invariant to test: Download URLs are host-validated against the authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with a hostile URL field asserting rejection.
