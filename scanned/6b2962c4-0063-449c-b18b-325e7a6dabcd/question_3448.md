# Q3448: argv injection into subprocess - newSCPCommand in ssh.go

## Question
Can an unprivileged attacker publish codespace/API response fields and everything the codespace-side process sends back that reaches `newSCPCommand` in [internal/codespaces/ssh.go](internal/codespaces/ssh.go#L107) and is appended to the subprocess argv without a `--` terminator, so a leading-dash value is parsed as an option by the spawned program?

## Target
- File/function: [internal/codespaces/ssh.go:107](internal/codespaces/ssh.go#L107) - `newSCPCommand`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo/branch/asset whose name begins with `--` (e.g. `--upload-pack=touch /tmp/pwn`) and let the victim run gh codespace ssh.
- Invariant to test: No value derived from remote data may be positioned where the child process can interpret it as a flag.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table-driven Go test stubbing the command runner; assert the recorded argv places attacker input after `--` and never as argv[i] starting with `-`.
