# Q1498: submodule fetch leaks credentials - (Updater).Update in updater.go

## Question
Can a submodule pointing at a non-GitHub host, processed via `Update` in [pkg/cmd/auth/shared/gitcredentials/updater.go](pkg/cmd/auth/shared/gitcredentials/updater.go#L18), cause the victim's credential helper to hand the GitHub token to that host?

## Target
- File/function: [pkg/cmd/auth/shared/gitcredentials/updater.go:18](pkg/cmd/auth/shared/gitcredentials/updater.go#L18) - `(Updater).Update`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo with `.gitmodules` pointing at `attacker.tld` and let the victim clone recursively.
- Invariant to test: Credential lookups are scoped to the authenticated host; recursive fetches do not inherit gh's helper for other hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Integration test with a hostile .gitmodules asserting no credential request for the foreign host.
