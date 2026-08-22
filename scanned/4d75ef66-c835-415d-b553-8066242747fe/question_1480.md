# Q1480: submodule fetch leaks credentials - NewCmdRefresh in refresh.go

## Question
Can a submodule pointing at a non-GitHub host, processed via `NewCmdRefresh` in [pkg/cmd/auth/refresh/refresh.go](pkg/cmd/auth/refresh/refresh.go#L43), cause the victim's credential helper to hand the GitHub token to that host?

## Target
- File/function: [pkg/cmd/auth/refresh/refresh.go:43](pkg/cmd/auth/refresh/refresh.go#L43) - `NewCmdRefresh`
- Entrypoint: gh auth refresh
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo with `.gitmodules` pointing at `attacker.tld` and let the victim clone recursively.
- Invariant to test: Credential lookups are scoped to the authenticated host; recursive fetches do not inherit gh's helper for other hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Integration test with a hostile .gitmodules asserting no credential request for the foreign host.
