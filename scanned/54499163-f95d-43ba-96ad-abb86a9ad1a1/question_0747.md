# Q0747: host list iteration authenticates the wrong one - getToken in multi_account.go

## Question
When multiple hosts/accounts are configured, can `getToken` in [internal/config/migration/multi_account.go](internal/config/migration/multi_account.go#L139) select one by ordering, map iteration, or first-match rather than by the operation's target host?

## Target
- File/function: [internal/config/migration/multi_account.go:139](internal/config/migration/multi_account.go#L139) - `getToken`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Add an attacker host to the flow so the wrong account is selected for the action.
- Invariant to test: Selection is deterministic and target-host driven.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with several configured hosts asserting the chosen account.
