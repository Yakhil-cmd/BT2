# Q3069: sync/push targets attacker remote - runGitCommands in develop.go

## Question
Can `runGitCommands` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L422) be steered by repo metadata into pushing the victim's local branches (possibly containing private code) to a remote the attacker controls?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:422](pkg/cmd/issue/develop/develop.go#L422) - `runGitCommands`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose upstream/parent metadata points at the attacker.
- Invariant to test: Push targets are confirmed and host-validated.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting the push remote for hostile metadata.
