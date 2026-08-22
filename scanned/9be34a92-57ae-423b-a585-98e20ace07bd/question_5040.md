# Q5040: host list iteration authenticates the wrong one - AuthFlow in flow.go

## Question
When multiple hosts/accounts are configured, can `AuthFlow` in [internal/authflow/flow.go](internal/authflow/flow.go#L30) select one by ordering, map iteration, or first-match rather than by the operation's target host?

## Target
- File/function: [internal/authflow/flow.go:30](internal/authflow/flow.go#L30) - `AuthFlow`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Add an attacker host to the flow so the wrong account is selected for the action.
- Invariant to test: Selection is deterministic and target-host driven.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with several configured hosts asserting the chosen account.
