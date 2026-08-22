# Q0327: submodule fetch leaks credentials - NewCmdInstall in install.go

## Question
Can a submodule pointing at a non-GitHub host, processed via `NewCmdInstall` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L76), cause the victim's credential helper to hand the GitHub token to that host?

## Target
- File/function: [pkg/cmd/skills/install/install.go:76](pkg/cmd/skills/install/install.go#L76) - `NewCmdInstall`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a repo with `.gitmodules` pointing at `attacker.tld` and let the victim clone recursively.
- Invariant to test: Credential lookups are scoped to the authenticated host; recursive fetches do not inherit gh's helper for other hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Integration test with a hostile .gitmodules asserting no credential request for the foreign host.
