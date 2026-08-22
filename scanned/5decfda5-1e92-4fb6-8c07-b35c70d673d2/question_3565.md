# Q3565: privileged action reached without confirmation via remote coordinates - (Context).findKeygen in ssh_keys.go

## Question
Can attacker-published coordinates flowing into `findKeygen` in [pkg/ssh/ssh_keys.go](pkg/ssh/ssh_keys.go#L102) cause a state-changing API call (delete, transfer, edit, secret write) against a target the user did not name?

## Target
- File/function: [pkg/ssh/ssh_keys.go:102](pkg/ssh/ssh_keys.go#L102) - `(Context).findKeygen`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish repo/remote metadata that wins resolution before the action.
- Invariant to test: State-changing operations confirm the fully qualified target resolved from user input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the target of the mutating request equals the user-specified one.
