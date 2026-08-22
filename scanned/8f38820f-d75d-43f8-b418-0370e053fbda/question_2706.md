# Q2706: retry amplification - NewCmdView in view.go

## Question
Can an attacker-controlled endpoint reached from `NewCmdView` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L42) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/issue/view/view.go:42](pkg/cmd/issue/view/view.go#L42) - `NewCmdView`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
