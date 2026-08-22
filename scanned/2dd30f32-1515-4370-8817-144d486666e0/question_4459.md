# Q4459: token attached to non-matching host - (gitExecuter).Fetch in git.go

## Question
Can `Fetch` in [pkg/cmd/repo/sync/git.go](pkg/cmd/repo/sync/git.go#L56) attach the token stored for one host to a request whose host was derived from a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes?

## Target
- File/function: [pkg/cmd/repo/sync/git.go:56](pkg/cmd/repo/sync/git.go#L56) - `(gitExecuter).Fetch`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo/remote that resolves to a host the attacker controls while the victim's active token is for github.com.
- Invariant to test: A token is only ever sent to the exact host it was issued for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test with two configured hosts asserting the header matches the request host.
