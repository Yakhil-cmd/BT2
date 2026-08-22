# Q2198: host list iteration authenticates the wrong one - NewCmdSwitch in switch.go

## Question
When multiple hosts/accounts are configured, can `NewCmdSwitch` in [pkg/cmd/auth/switch/switch.go](pkg/cmd/auth/switch/switch.go#L24) select one by ordering, map iteration, or first-match rather than by the operation's target host?

## Target
- File/function: [pkg/cmd/auth/switch/switch.go:24](pkg/cmd/auth/switch/switch.go#L24) - `NewCmdSwitch`
- Entrypoint: gh auth switch
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Add an attacker host to the flow so the wrong account is selected for the action.
- Invariant to test: Selection is deterministic and target-host driven.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with several configured hosts asserting the chosen account.
