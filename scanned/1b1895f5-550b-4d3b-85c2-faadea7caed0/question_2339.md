# Q2339: credentials sent to the remote of a hostile repo - ParseFullReference in finder.go

## Question
When `ParseFullReference` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L335) invokes git for a repository whose remote host came from attacker-published metadata, is gh's credential helper still active for that invocation?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:335](pkg/cmd/pr/shared/finder.go#L335) - `ParseFullReference`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose remote is `https://github.com.evil.tld/x` and let the victim run gh pr.
- Invariant to test: gh authenticates git only for hosts it holds credentials for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the helper is not configured for foreign hosts.
