# Q3547: privileged action reached without confirmation via remote coordinates - NewCmdSet in set.go

## Question
Can attacker-published coordinates flowing into `NewCmdSet` in [pkg/cmd/alias/set/set.go](pkg/cmd/alias/set/set.go#L29) cause a state-changing API call (delete, transfer, edit, secret write) against a target the user did not name?

## Target
- File/function: [pkg/cmd/alias/set/set.go:29](pkg/cmd/alias/set/set.go#L29) - `NewCmdSet`
- Entrypoint: gh alias set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish repo/remote metadata that wins resolution before the action.
- Invariant to test: State-changing operations confirm the fully qualified target resolved from user input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the target of the mutating request equals the user-specified one.
