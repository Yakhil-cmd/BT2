# Q2136: secret value or key leaked on error - (Context).GenerateSSHKey in ssh_keys.go

## Question
Can an error path in `GenerateSSHKey` in [pkg/ssh/ssh_keys.go](pkg/ssh/ssh_keys.go#L51) print the plaintext secret, the public key, or the encrypted payload alongside the target repo when the target was influenced by attacker-published coordinates?

## Target
- File/function: [pkg/ssh/ssh_keys.go:51](pkg/ssh/ssh_keys.go#L51) - `(Context).GenerateSSHKey`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Cause the upload to fail against attacker coordinates.
- Invariant to test: Secret material never appears in output and targets are confirmed before encryption.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test forcing the error asserting no secret material in output.
