# Q1635: credentials sent to the remote of a hostile repo - developRun in develop.go

## Question
When `developRun` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L167) invokes git for a repository whose remote host came from attacker-published metadata, is gh's credential helper still active for that invocation?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:167](pkg/cmd/issue/develop/develop.go#L167) - `developRun`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose remote is `https://github.com.evil.tld/x` and let the victim run gh issue develop.
- Invariant to test: gh authenticates git only for hosts it holds credentials for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the helper is not configured for foreign hosts.
