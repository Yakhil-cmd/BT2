# Q3689: submodule fetch leaks credentials - branchFunc in default.go

## Question
Can a submodule pointing at a non-GitHub host, processed via `branchFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L262), cause the victim's credential helper to hand the GitHub token to that host?

## Target
- File/function: [pkg/cmd/factory/default.go:262](pkg/cmd/factory/default.go#L262) - `branchFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo with `.gitmodules` pointing at `attacker.tld` and let the victim clone recursively.
- Invariant to test: Credential lookups are scoped to the authenticated host; recursive fetches do not inherit gh's helper for other hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Integration test with a hostile .gitmodules asserting no credential request for the foreign host.
