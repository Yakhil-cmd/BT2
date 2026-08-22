# Q1603: sync/push targets attacker remote - (gitExecuter).Fetch in git.go

## Question
Can `Fetch` in [pkg/cmd/repo/sync/git.go](pkg/cmd/repo/sync/git.go#L56) be steered by repo metadata into pushing the victim's local branches (possibly containing private code) to a remote the attacker controls?

## Target
- File/function: [pkg/cmd/repo/sync/git.go:56](pkg/cmd/repo/sync/git.go#L56) - `(gitExecuter).Fetch`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose upstream/parent metadata points at the attacker.
- Invariant to test: Push targets are confirmed and host-validated.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting the push remote for hostile metadata.
