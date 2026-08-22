# Q1363: retry amplification - newPortsCmd in ports.go

## Question
Can an attacker-controlled endpoint reached from `newPortsCmd` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L27) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/codespace/ports.go:27](pkg/cmd/codespace/ports.go#L27) - `newPortsCmd`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
