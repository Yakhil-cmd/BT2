# Q2122: secret value or key leaked on error - importRun in import.go

## Question
Can an error path in `importRun` in [pkg/cmd/alias/imports/import.go](pkg/cmd/alias/imports/import.go#L94) print the plaintext secret, the public key, or the encrypted payload alongside the target repo when the target was influenced by attacker-published coordinates?

## Target
- File/function: [pkg/cmd/alias/imports/import.go:94](pkg/cmd/alias/imports/import.go#L94) - `importRun`
- Entrypoint: gh alias imports
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Cause the upload to fail against attacker coordinates.
- Invariant to test: Secret material never appears in output and targets are confirmed before encryption.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test forcing the error asserting no secret material in output.
