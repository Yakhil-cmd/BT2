# Q1012: registry response controls the download URL - acquireFLock in lockfile.go

## Question
Can the registry/search response consumed by `acquireFLock` in [internal/skills/lockfile/lockfile.go](internal/skills/lockfile/lockfile.go#L155) point the download at an arbitrary host or path?

## Target
- File/function: [internal/skills/lockfile/lockfile.go:155](internal/skills/lockfile/lockfile.go#L155) - `acquireFLock`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a registry entry whose URL field targets the attacker's server.
- Invariant to test: Download URLs are host-validated against the authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with a hostile URL field asserting rejection.
