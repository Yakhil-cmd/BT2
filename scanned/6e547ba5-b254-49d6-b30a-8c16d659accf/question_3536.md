# Q3536: unvalidated shell-ish string join - runCopilot in copilot.go

## Question
Does `runCopilot` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L134) build its command by string concatenation or `shlex`-style splitting of a value that includes an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes, rather than passing a fixed argv slice?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:134](pkg/cmd/copilot/copilot.go#L134) - `runCopilot`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Embed spaces/quotes in the remote-controlled field so the split produces extra arguments.
- Invariant to test: Commands are always constructed as explicit argv slices.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Unit test asserting a value containing spaces and quotes yields exactly one argv element.
