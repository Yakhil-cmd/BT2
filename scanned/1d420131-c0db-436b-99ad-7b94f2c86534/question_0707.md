# Q0707: deletion of attacker-chosen path - (Context).LocalPublicKeys in ssh_keys.go

## Question
Can an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes steer the cleanup/RemoveAll in `LocalPublicKeys` in [pkg/ssh/ssh_keys.go](pkg/ssh/ssh_keys.go#L37) at a path outside the directory gh created?

## Target
- File/function: [pkg/ssh/ssh_keys.go:37](pkg/ssh/ssh_keys.go#L37) - `(Context).LocalPublicKeys`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a name that resolves outside the install/download root so the cleanup deletes victim data.
- Invariant to test: Removal targets only paths gh itself created inside its own root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the removal path is validated with the same root check as writes.
