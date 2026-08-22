# Q3623: host list iteration authenticates the wrong one - refreshRun in refresh.go

## Question
When multiple hosts/accounts are configured, can `refreshRun` in [pkg/cmd/auth/refresh/refresh.go](pkg/cmd/auth/refresh/refresh.go#L127) select one by ordering, map iteration, or first-match rather than by the operation's target host?

## Target
- File/function: [pkg/cmd/auth/refresh/refresh.go:127](pkg/cmd/auth/refresh/refresh.go#L127) - `refreshRun`
- Entrypoint: gh auth refresh
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Add an attacker host to the flow so the wrong account is selected for the action.
- Invariant to test: Selection is deterministic and target-host driven.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with several configured hosts asserting the chosen account.
