# Q0757: scope elevation without user consent - AuthFlow in flow.go

## Question
Can the flow in `AuthFlow` in [internal/authflow/flow.go](internal/authflow/flow.go#L30) request or persist a broader OAuth scope set than the user approved for the operation actually being run?

## Target
- File/function: [internal/authflow/flow.go:30](internal/authflow/flow.go#L30) - `AuthFlow`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Trigger a path that silently refreshes with extra scopes while the user believes they authorized a read-only action.
- Invariant to test: Scope requests match the operation and are shown before authorization.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the scope list sent equals the minimum for the command.
