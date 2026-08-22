# Q2991: git -c config injection - (Client).Command in client.go

## Question
Can a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes reach `Command` in [git/client.go](git/client.go#L77) and land inside a `-c key=value` / config argument, letting an attacker set an execution-bearing git config such as `core.fsmonitor`, `core.sshCommand`, `protocol.ext.allow`, or an alias?

## Target
- File/function: [git/client.go:77](git/client.go#L77) - `(Client).Command`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo or ref whose name embeds `=` and newline characters so the assembled config pair splits into an extra execution-bearing key.
- Invariant to test: Config keys and values sent to git are fixed by gh, never assembled from remote strings.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Fuzz the argument builder with names containing `=`, newline, and NUL; assert only allowlisted config keys are emitted.
