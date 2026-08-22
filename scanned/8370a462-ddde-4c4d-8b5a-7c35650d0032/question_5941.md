# Q5941: retry amplification - DiscoverSkillByPathWithOptions in discovery.go

## Question
Can an attacker-controlled endpoint reached from `DiscoverSkillByPathWithOptions` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L716) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [internal/skills/discovery/discovery.go:716](internal/skills/discovery/discovery.go#L716) - `DiscoverSkillByPathWithOptions`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
