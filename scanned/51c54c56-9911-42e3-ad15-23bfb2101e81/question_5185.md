# Q5185: concurrent temp path reuse - executeCmds in checkout.go

## Question
Does `executeCmds` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L356) write a script/temp file at a predictable path before executing it, so a second attacker-triggered gh flow can swap its contents between write and exec?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:356](pkg/cmd/pr/checkout/checkout.go#L356) - `executeCmds`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Trigger two gh operations on attacker content that collide on the same deterministic temp path.
- Invariant to test: Executed temp artifacts are created with O_EXCL in a per-run random directory.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test that two sequential calls produce distinct paths and that creation uses exclusive flags.
