# Q5853: submodule fetch leaks credentials - NewCmdDevelop in develop.go

## Question
Can a submodule pointing at a non-GitHub host, processed via `NewCmdDevelop` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L40), cause the victim's credential helper to hand the GitHub token to that host?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:40](pkg/cmd/issue/develop/develop.go#L40) - `NewCmdDevelop`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo with `.gitmodules` pointing at `attacker.tld` and let the victim clone recursively.
- Invariant to test: Credential lookups are scoped to the authenticated host; recursive fetches do not inherit gh's helper for other hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Integration test with a hostile .gitmodules asserting no credential request for the foreign host.
