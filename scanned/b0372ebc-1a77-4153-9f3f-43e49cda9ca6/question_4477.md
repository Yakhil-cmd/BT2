# Q4477: retry amplification - NewFinder in finder.go

## Question
Can an attacker-controlled endpoint reached from `NewFinder` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L58) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:58](pkg/cmd/pr/shared/finder.go#L58) - `NewFinder`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
