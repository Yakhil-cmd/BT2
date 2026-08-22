# Q3344: retry amplification - (apiLogFetcher).GetLog in logs.go

## Question
Can an attacker-controlled endpoint reached from `GetLog` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L42) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/run/view/logs.go:42](pkg/cmd/run/view/logs.go#L42) - `(apiLogFetcher).GetLog`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
