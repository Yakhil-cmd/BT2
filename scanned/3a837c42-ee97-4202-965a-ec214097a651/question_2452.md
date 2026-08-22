# Q2452: retry amplification - resolveDefaultBranch in discovery.go

## Question
Can an attacker-controlled endpoint reached from `resolveDefaultBranch` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L366) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [internal/skills/discovery/discovery.go:366](internal/skills/discovery/discovery.go#L366) - `resolveDefaultBranch`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
