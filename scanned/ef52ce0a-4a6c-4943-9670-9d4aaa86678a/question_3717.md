# Q3717: attacker text written into git config - parseBranchConfig in client.go

## Question
Can a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes flowing through `parseBranchConfig` in [git/client.go](git/client.go#L453) be written into the repository's git config with newlines, creating an extra config section such as an alias or `core.sshCommand`?

## Target
- File/function: [git/client.go:453](git/client.go#L453) - `parseBranchConfig`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Use a branch/remote name containing a newline and a config-looking line.
- Invariant to test: Values are validated to exclude newlines before any config write.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting a newline-bearing value is rejected.
