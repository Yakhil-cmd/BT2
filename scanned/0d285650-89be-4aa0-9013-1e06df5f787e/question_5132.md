# Q5132: concurrent temp path reuse - (Client).Command in client.go

## Question
Does `Command` in [git/client.go](git/client.go#L77) write a script/temp file at a predictable path before executing it, so a second attacker-triggered gh flow can swap its contents between write and exec?

## Target
- File/function: [git/client.go:77](git/client.go#L77) - `(Client).Command`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Trigger two gh operations on attacker content that collide on the same deterministic temp path.
- Invariant to test: Executed temp artifacts are created with O_EXCL in a per-run random directory.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test that two sequential calls produce distinct paths and that creation uses exclusive flags.
