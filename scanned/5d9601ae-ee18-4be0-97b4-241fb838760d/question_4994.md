# Q4994: privileged action reached without confirmation via remote coordinates - CheckForUpdate in update.go

## Question
Can attacker-published coordinates flowing into `CheckForUpdate` in [internal/update/update.go](internal/update/update.go#L92) cause a state-changing API call (delete, transfer, edit, secret write) against a target the user did not name?

## Target
- File/function: [internal/update/update.go:92](internal/update/update.go#L92) - `CheckForUpdate`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish repo/remote metadata that wins resolution before the action.
- Invariant to test: State-changing operations confirm the fully qualified target resolved from user input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the target of the mutating request equals the user-specified one.
