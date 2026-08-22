# Q1381: retry amplification - filterCodespacesByRepoOwner in common.go

## Question
Can an attacker-controlled endpoint reached from `filterCodespacesByRepoOwner` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L262) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/codespace/common.go:262](pkg/cmd/codespace/common.go#L262) - `filterCodespacesByRepoOwner`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
