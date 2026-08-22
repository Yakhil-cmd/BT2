# Q4165: retry amplification - GetCodespaceConnection in codespaces.go

## Question
Can an attacker-controlled endpoint reached from `GetCodespaceConnection` in [internal/codespaces/codespaces.go](internal/codespaces/codespaces.go#L60) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [internal/codespaces/codespaces.go:60](internal/codespaces/codespaces.go#L60) - `GetCodespaceConnection`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
