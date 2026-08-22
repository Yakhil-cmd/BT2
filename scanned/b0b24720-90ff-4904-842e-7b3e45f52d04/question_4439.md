# Q4439: token attached to non-matching host - (Client).Pull in client.go

## Question
Can `Pull` in [git/client.go](git/client.go#L881) attach the token stored for one host to a request whose host was derived from a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes?

## Target
- File/function: [git/client.go:881](git/client.go#L881) - `(Client).Pull`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo/remote that resolves to a host the attacker controls while the victim's active token is for github.com.
- Invariant to test: A token is only ever sent to the exact host it was issued for.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test with two configured hosts asserting the header matches the request host.
