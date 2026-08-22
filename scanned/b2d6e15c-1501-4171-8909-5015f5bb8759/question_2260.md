# Q2260: timeout/EOF treated as approval - newPrompter in default.go

## Question
Does an EOF or closed stdin in `newPrompter` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L256) resolve to the affirmative branch?

## Target
- File/function: [pkg/cmd/factory/default.go:256](pkg/cmd/factory/default.go#L256) - `newPrompter`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Run the flow with stdin closed, as in a CI pipeline processing attacker content.
- Invariant to test: EOF is an error, never a yes.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a closed stdin asserting an error.
