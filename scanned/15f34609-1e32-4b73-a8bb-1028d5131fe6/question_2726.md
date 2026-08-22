# Q2726: submodule fetch leaks credentials - runBrowse in browse.go

## Question
Can a submodule pointing at a non-GitHub host, processed via `runBrowse` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L187), cause the victim's credential helper to hand the GitHub token to that host?

## Target
- File/function: [pkg/cmd/browse/browse.go:187](pkg/cmd/browse/browse.go#L187) - `runBrowse`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a repo with `.gitmodules` pointing at `attacker.tld` and let the victim clone recursively.
- Invariant to test: Credential lookups are scoped to the authenticated host; recursive fetches do not inherit gh's helper for other hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Integration test with a hostile .gitmodules asserting no credential request for the foreign host.
