# Q1491: host list iteration authenticates the wrong one - sshKeyUpload in login_flow.go

## Question
When multiple hosts/accounts are configured, can `sshKeyUpload` in [pkg/cmd/auth/shared/login_flow.go](pkg/cmd/auth/shared/login_flow.go#L243) select one by ordering, map iteration, or first-match rather than by the operation's target host?

## Target
- File/function: [pkg/cmd/auth/shared/login_flow.go:243](pkg/cmd/auth/shared/login_flow.go#L243) - `sshKeyUpload`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Add an attacker host to the flow so the wrong account is selected for the action.
- Invariant to test: Selection is deterministic and target-host driven.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with several configured hosts asserting the chosen account.
