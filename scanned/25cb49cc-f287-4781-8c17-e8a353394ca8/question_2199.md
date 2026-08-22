# Q2199: timeout/EOF treated as approval - switchRun in switch.go

## Question
Does an EOF or closed stdin in `switchRun` in [pkg/cmd/auth/switch/switch.go](pkg/cmd/auth/switch/switch.go#L77) resolve to the affirmative branch?

## Target
- File/function: [pkg/cmd/auth/switch/switch.go:77](pkg/cmd/auth/switch/switch.go#L77) - `switchRun`
- Entrypoint: gh auth switch
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Run the flow with stdin closed, as in a CI pipeline processing attacker content.
- Invariant to test: EOF is an error, never a yes.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a closed stdin asserting an error.
