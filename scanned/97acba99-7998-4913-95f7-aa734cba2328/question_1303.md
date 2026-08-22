# Q1303: concurrent temp path reuse - Shell in ssh.go

## Question
Does `Shell` in [internal/codespaces/ssh.go](internal/codespaces/ssh.go#L21) write a script/temp file at a predictable path before executing it, so a second attacker-triggered gh flow can swap its contents between write and exec?

## Target
- File/function: [internal/codespaces/ssh.go:21](internal/codespaces/ssh.go#L21) - `Shell`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Trigger two gh operations on attacker content that collide on the same deterministic temp path.
- Invariant to test: Executed temp artifacts are created with O_EXCL in a per-run random directory.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test that two sequential calls produce distinct paths and that creation uses exclusive flags.
