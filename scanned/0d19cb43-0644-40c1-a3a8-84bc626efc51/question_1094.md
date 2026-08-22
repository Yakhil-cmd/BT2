# Q1094: retry amplification - addAgentSkillsTopic in publish.go

## Question
Can an attacker-controlled endpoint reached from `addAgentSkillsTopic` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L708) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:708](pkg/cmd/skills/publish/publish.go#L708) - `addAgentSkillsTopic`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
