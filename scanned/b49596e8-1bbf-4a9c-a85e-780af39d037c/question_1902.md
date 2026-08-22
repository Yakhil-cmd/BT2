# Q1902: retry amplification - StubFetchRefSHA in fetch.go

## Question
Can an attacker-controlled endpoint reached from `StubFetchRefSHA` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L329) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:329](pkg/cmd/release/shared/fetch.go#L329) - `StubFetchRefSHA`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
