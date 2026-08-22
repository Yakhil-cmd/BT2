# Q3737: attacker text written into git config - NewCmdClone in clone.go

## Question
Can a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes flowing through `NewCmdClone` in [pkg/cmd/repo/clone/clone.go](pkg/cmd/repo/clone/clone.go#L33) be written into the repository's git config with newlines, creating an extra config section such as an alias or `core.sshCommand`?

## Target
- File/function: [pkg/cmd/repo/clone/clone.go:33](pkg/cmd/repo/clone/clone.go#L33) - `NewCmdClone`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Use a branch/remote name containing a newline and a config-looking line.
- Invariant to test: Values are validated to exclude newlines before any config write.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting a newline-bearing value is rejected.
