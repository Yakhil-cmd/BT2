# Q3446: git -c config injection - Copy in ssh.go

## Question
Can codespace/API response fields and everything the codespace-side process sends back reach `Copy` in [internal/codespaces/ssh.go](internal/codespaces/ssh.go#L42) and land inside a `-c key=value` / config argument, letting an attacker set an execution-bearing git config such as `core.fsmonitor`, `core.sshCommand`, `protocol.ext.allow`, or an alias?

## Target
- File/function: [internal/codespaces/ssh.go:42](internal/codespaces/ssh.go#L42) - `Copy`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo or ref whose name embeds `=` and newline characters so the assembled config pair splits into an extra execution-bearing key.
- Invariant to test: Config keys and values sent to git are fixed by gh, never assembled from remote strings.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Fuzz the argument builder with names containing `=`, newline, and NUL; assert only allowlisted config keys are emitted.
