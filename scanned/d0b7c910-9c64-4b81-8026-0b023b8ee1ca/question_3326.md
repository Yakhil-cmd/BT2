# Q3326: retry amplification - FetchLatestRelease in fetch.go

## Question
Can an attacker-controlled endpoint reached from `FetchLatestRelease` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L237) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:237](pkg/cmd/release/shared/fetch.go#L237) - `FetchLatestRelease`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
