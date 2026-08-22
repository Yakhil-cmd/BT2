# Q2891: scope elevation without user consent - migrateToken in multi_account.go

## Question
Can the flow in `migrateToken` in [internal/config/migration/multi_account.go](internal/config/migration/multi_account.go#L188) request or persist a broader OAuth scope set than the user approved for the operation actually being run?

## Target
- File/function: [internal/config/migration/multi_account.go:188](internal/config/migration/multi_account.go#L188) - `migrateToken`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Trigger a path that silently refreshes with extra scopes while the user believes they authorized a read-only action.
- Invariant to test: Scope requests match the operation and are shown before authorization.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the scope list sent equals the minimum for the command.
