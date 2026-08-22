# Q1678: submodule fetch leaks credentials - (gitExecuter).Clone in git.go

## Question
Can a submodule pointing at a non-GitHub host, processed via `Clone` in [pkg/cmd/extension/git.go](pkg/cmd/extension/git.go#L28), cause the victim's credential helper to hand the GitHub token to that host?

## Target
- File/function: [pkg/cmd/extension/git.go:28](pkg/cmd/extension/git.go#L28) - `(gitExecuter).Clone`
- Entrypoint: gh extension git
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a repo with `.gitmodules` pointing at `attacker.tld` and let the victim clone recursively.
- Invariant to test: Credential lookups are scoped to the authenticated host; recursive fetches do not inherit gh's helper for other hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Integration test with a hostile .gitmodules asserting no credential request for the foreign host.
