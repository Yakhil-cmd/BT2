# Q4967: argv injection into subprocess - findCopilotBinary in copilot.go

## Question
Can an unprivileged attacker publish an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes that reaches `findCopilotBinary` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L225) and is appended to the subprocess argv without a `--` terminator, so a leading-dash value is parsed as an option by the spawned program?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:225](pkg/cmd/copilot/copilot.go#L225) - `findCopilotBinary`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a repo/branch/asset whose name begins with `--` (e.g. `--upload-pack=touch /tmp/pwn`) and let the victim run gh copilot copilot.
- Invariant to test: No value derived from remote data may be positioned where the child process can interpret it as a flag.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table-driven Go test stubbing the command runner; assert the recorded argv places attacker input after `--` and never as argv[i] starting with `-`.
