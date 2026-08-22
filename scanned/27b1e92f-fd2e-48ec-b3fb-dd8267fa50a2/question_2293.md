# Q2293: sync/push targets attacker remote - (Client).HasLocalBranch in client.go

## Question
Can `HasLocalBranch` in [git/client.go](git/client.go#L693) be steered by repo metadata into pushing the victim's local branches (possibly containing private code) to a remote the attacker controls?

## Target
- File/function: [git/client.go:693](git/client.go#L693) - `(Client).HasLocalBranch`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose upstream/parent metadata points at the attacker.
- Invariant to test: Push targets are confirmed and host-validated.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting the push remote for hostile metadata.
