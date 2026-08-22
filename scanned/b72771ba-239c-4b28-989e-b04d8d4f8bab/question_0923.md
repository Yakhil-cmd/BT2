# Q0923: unbounded response body - linkedBranchRepoFromURL in develop.go

## Question
Does `linkedBranchRepoFromURL` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L306) read the whole response body into memory without a limit, so an attacker-controlled endpoint can exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:306](pkg/cmd/issue/develop/develop.go#L306) - `linkedBranchRepoFromURL`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Serve a multi-gigabyte body from an attacker-controlled host or asset URL.
- Invariant to test: Response reads are wrapped in a limit reader with an explicit cap.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a huge/endless body asserting a bounded error.
