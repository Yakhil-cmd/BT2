# Q2075: security decision from response field - newCpCmd in ssh.go

## Question
Does `newCpCmd` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L710) branch on a boolean/permission/visibility field of the response that the attacker owns (their repo, their codespace, their gist) to decide what to write, execute, or trust locally?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:710](pkg/cmd/codespace/ssh.go#L710) - `newCpCmd`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish an object with the field flipped and observe the local behaviour change.
- Invariant to test: Local trust decisions never depend on attacker-owned object fields.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test flipping the field asserting no change to the local security-relevant action.
