# Q2810: retry amplification - NewCAPIClient in client.go

## Question
Can an attacker-controlled endpoint reached from `NewCAPIClient` in [pkg/cmd/agent-task/capi/client.go](pkg/cmd/agent-task/capi/client.go#L36) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/agent-task/capi/client.go:36](pkg/cmd/agent-task/capi/client.go#L36) - `NewCAPIClient`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
