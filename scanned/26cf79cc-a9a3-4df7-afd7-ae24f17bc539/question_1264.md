# Q1264: submodule fetch leaks credentials - FormatSlice in text.go

## Question
Can a submodule pointing at a non-GitHub host, processed via `FormatSlice` in [internal/text/text.go](internal/text/text.go#L97), cause the victim's credential helper to hand the GitHub token to that host?

## Target
- File/function: [internal/text/text.go:97](internal/text/text.go#L97) - `FormatSlice`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a repo with `.gitmodules` pointing at `attacker.tld` and let the victim clone recursively.
- Invariant to test: Credential lookups are scoped to the authenticated host; recursive fetches do not inherit gh's helper for other hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Integration test with a hostile .gitmodules asserting no credential request for the foreign host.
