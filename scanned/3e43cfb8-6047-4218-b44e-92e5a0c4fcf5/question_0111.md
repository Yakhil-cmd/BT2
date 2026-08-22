# Q0111: retry amplification - SmartBaseRepoFunc in default.go

## Question
Can an attacker-controlled endpoint reached from `SmartBaseRepoFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L152) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/factory/default.go:152](pkg/cmd/factory/default.go#L152) - `SmartBaseRepoFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
