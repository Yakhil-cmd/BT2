# Q5851: credentials sent to the remote of a hostile repo - preloadPrChecks in finder.go

## Question
When `preloadPrChecks` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L563) invokes git for a repository whose remote host came from attacker-published metadata, is gh's credential helper still active for that invocation?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:563](pkg/cmd/pr/shared/finder.go#L563) - `preloadPrChecks`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose remote is `https://github.com.evil.tld/x` and let the victim run gh pr.
- Invariant to test: gh authenticates git only for hosts it holds credentials for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the helper is not configured for foreign hosts.
