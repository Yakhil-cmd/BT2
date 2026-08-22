# Q0887: credentials sent to the remote of a hostile repo - (gitExecuter).CreateBranch in git.go

## Question
When `CreateBranch` in [pkg/cmd/repo/sync/git.go](pkg/cmd/repo/sync/git.go#L35) invokes git for a repository whose remote host came from attacker-published metadata, is gh's credential helper still active for that invocation?

## Target
- File/function: [pkg/cmd/repo/sync/git.go:35](pkg/cmd/repo/sync/git.go#L35) - `(gitExecuter).CreateBranch`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose remote is `https://github.com.evil.tld/x` and let the victim run gh repo sync.
- Invariant to test: gh authenticates git only for hosts it holds credentials for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the helper is not configured for foreign hosts.
