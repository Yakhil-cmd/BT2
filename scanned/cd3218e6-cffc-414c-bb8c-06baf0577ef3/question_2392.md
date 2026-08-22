# Q2392: attacker text written into git config - (gitExecuter).Clone in git.go

## Question
Can an extension repository, its release assets, and its manifest fields flowing through `Clone` in [pkg/cmd/extension/git.go](pkg/cmd/extension/git.go#L28) be written into the repository's git config with newlines, creating an extra config section such as an alias or `core.sshCommand`?

## Target
- File/function: [pkg/cmd/extension/git.go:28](pkg/cmd/extension/git.go#L28) - `(gitExecuter).Clone`
- Entrypoint: gh extension git
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Use a branch/remote name containing a newline and a config-looking line.
- Invariant to test: Values are validated to exclude newlines before any config write.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting a newline-bearing value is rejected.
