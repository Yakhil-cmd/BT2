# Q3220: retry amplification - renderAllFiles in preview.go

## Question
Can an attacker-controlled endpoint reached from `renderAllFiles` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L267) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:267](pkg/cmd/skills/preview/preview.go#L267) - `renderAllFiles`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
