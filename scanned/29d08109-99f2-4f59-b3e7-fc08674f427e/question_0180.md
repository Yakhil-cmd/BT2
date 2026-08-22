# Q0180: retry amplification - executeRemoteRepoSync in sync.go

## Question
Can an attacker-controlled endpoint reached from `executeRemoteRepoSync` in [pkg/cmd/repo/sync/sync.go](pkg/cmd/repo/sync/sync.go#L281) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/repo/sync/sync.go:281](pkg/cmd/repo/sync/sync.go#L281) - `executeRemoteRepoSync`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
