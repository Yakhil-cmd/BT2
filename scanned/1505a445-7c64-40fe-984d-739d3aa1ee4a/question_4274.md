# Q4274: privileged action reached without confirmation via remote coordinates - putOrgSecret in http.go

## Question
Can attacker-published coordinates flowing into `putOrgSecret` in [pkg/cmd/secret/set/http.go](pkg/cmd/secret/set/http.go#L85) cause a state-changing API call (delete, transfer, edit, secret write) against a target the user did not name?

## Target
- File/function: [pkg/cmd/secret/set/http.go:85](pkg/cmd/secret/set/http.go#L85) - `putOrgSecret`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish repo/remote metadata that wins resolution before the action.
- Invariant to test: State-changing operations confirm the fully qualified target resolved from user input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the target of the mutating request equals the user-specified one.
