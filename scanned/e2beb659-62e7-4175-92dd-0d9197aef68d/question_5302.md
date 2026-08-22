# Q5302: submodule fetch leaks credentials - resolveTagRef in discovery.go

## Question
Can a submodule pointing at a non-GitHub host, processed via `resolveTagRef` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L276), cause the victim's credential helper to hand the GitHub token to that host?

## Target
- File/function: [internal/skills/discovery/discovery.go:276](internal/skills/discovery/discovery.go#L276) - `resolveTagRef`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a repo with `.gitmodules` pointing at `attacker.tld` and let the victim clone recursively.
- Invariant to test: Credential lookups are scoped to the authenticated host; recursive fetches do not inherit gh's helper for other hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Integration test with a hostile .gitmodules asserting no credential request for the foreign host.
