# Q4154: retry amplification - runBrowse in browse.go

## Question
Can an attacker-controlled endpoint reached from `runBrowse` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L187) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/browse/browse.go:187](pkg/cmd/browse/browse.go#L187) - `runBrowse`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
