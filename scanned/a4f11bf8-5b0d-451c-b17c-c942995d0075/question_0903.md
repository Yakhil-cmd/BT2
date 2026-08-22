# Q0903: unvalidated shell-ish string join - authenticatedCommand in checkout.go

## Question
Does `authenticatedCommand` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L388) build its command by string concatenation or `shlex`-style splitting of a value that includes a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes, rather than passing a fixed argv slice?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:388](pkg/cmd/pr/checkout/checkout.go#L388) - `authenticatedCommand`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Embed spaces/quotes in the remote-controlled field so the split produces extra arguments.
- Invariant to test: Commands are always constructed as explicit argv slices.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Unit test asserting a value containing spaces and quotes yields exactly one argv element.
