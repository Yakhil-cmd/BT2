# Q0590: unvalidated shell-ish string join - Copy in ssh.go

## Question
Does `Copy` in [internal/codespaces/ssh.go](internal/codespaces/ssh.go#L42) build its command by string concatenation or `shlex`-style splitting of a value that includes codespace/API response fields and everything the codespace-side process sends back, rather than passing a fixed argv slice?

## Target
- File/function: [internal/codespaces/ssh.go:42](internal/codespaces/ssh.go#L42) - `Copy`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Embed spaces/quotes in the remote-controlled field so the split produces extra arguments.
- Invariant to test: Commands are always constructed as explicit argv slices.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Unit test asserting a value containing spaces and quotes yields exactly one argv element.
