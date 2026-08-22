# Q2782: timeout/EOF treated as approval - (App).SSH in ssh.go

## Question
Does an EOF or closed stdin in `SSH` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L165) resolve to the affirmative branch?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:165](pkg/cmd/codespace/ssh.go#L165) - `(App).SSH`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Run the flow with stdin closed, as in a CI pipeline processing attacker content.
- Invariant to test: EOF is an error, never a yes.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a closed stdin asserting an error.
