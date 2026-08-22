# Q5691: privileged action reached without confirmation via remote coordinates - ValidAliasNameFunc in validations.go

## Question
Can attacker-published coordinates flowing into `ValidAliasNameFunc` in [pkg/cmd/alias/shared/validations.go](pkg/cmd/alias/shared/validations.go#L15) cause a state-changing API call (delete, transfer, edit, secret write) against a target the user did not name?

## Target
- File/function: [pkg/cmd/alias/shared/validations.go:15](pkg/cmd/alias/shared/validations.go#L15) - `ValidAliasNameFunc`
- Entrypoint: gh alias
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish repo/remote metadata that wins resolution before the action.
- Invariant to test: State-changing operations confirm the fully qualified target resolved from user input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the target of the mutating request equals the user-specified one.
