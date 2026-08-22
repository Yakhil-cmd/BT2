# Q0931: concurrent temp path reuse - NewManager in manager.go

## Question
Does `NewManager` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L59) write a script/temp file at a predictable path before executing it, so a second attacker-triggered gh flow can swap its contents between write and exec?

## Target
- File/function: [pkg/cmd/extension/manager.go:59](pkg/cmd/extension/manager.go#L59) - `NewManager`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Trigger two gh operations on attacker content that collide on the same deterministic temp path.
- Invariant to test: Executed temp artifacts are created with O_EXCL in a per-run random directory.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test that two sequential calls produce distinct paths and that creation uses exclusive flags.
