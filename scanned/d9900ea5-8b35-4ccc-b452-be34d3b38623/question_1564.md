# Q1564: credentials sent to the remote of a hostile repo - CredentialPatternFromGitURL in client.go

## Question
When `CredentialPatternFromGitURL` in [git/client.go](git/client.go#L123) invokes git for a repository whose remote host came from attacker-published metadata, is gh's credential helper still active for that invocation?

## Target
- File/function: [git/client.go:123](git/client.go#L123) - `CredentialPatternFromGitURL`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose remote is `https://github.com.evil.tld/x` and let the victim run gh repo clone.
- Invariant to test: gh authenticates git only for hosts it holds credentials for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the helper is not configured for foreign hosts.
