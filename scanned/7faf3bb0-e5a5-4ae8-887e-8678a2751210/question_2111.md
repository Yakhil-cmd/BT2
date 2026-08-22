# Q2111: git -c config injection - runExternalCmd in copilot.go

## Question
Can an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes reach `runExternalCmd` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L213) and land inside a `-c key=value` / config argument, letting an attacker set an execution-bearing git config such as `core.fsmonitor`, `core.sshCommand`, `protocol.ext.allow`, or an alias?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:213](pkg/cmd/copilot/copilot.go#L213) - `runExternalCmd`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a repo or ref whose name embeds `=` and newline characters so the assembled config pair splits into an extra execution-bearing key.
- Invariant to test: Config keys and values sent to git are fixed by gh, never assembled from remote strings.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Fuzz the argument builder with names containing `=`, newline, and NUL; assert only allowlisted config keys are emitted.
