# Q5674: unauthenticated fallback on error - followLogs in create.go

## Question
When authentication fails inside `followLogs` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L263), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:263](pkg/cmd/agent-task/create/create.go#L263) - `followLogs`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
