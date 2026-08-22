# Q3073: unvalidated shell-ish string join - NewManager in manager.go

## Question
Does `NewManager` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L59) build its command by string concatenation or `shlex`-style splitting of a value that includes an extension repository, its release assets, and its manifest fields, rather than passing a fixed argv slice?

## Target
- File/function: [pkg/cmd/extension/manager.go:59](pkg/cmd/extension/manager.go#L59) - `NewManager`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Embed spaces/quotes in the remote-controlled field so the split produces extra arguments.
- Invariant to test: Commands are always constructed as explicit argv slices.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Unit test asserting a value containing spaces and quotes yields exactly one argv element.
