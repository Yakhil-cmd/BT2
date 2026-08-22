# Q5580: attacker text written into git config - runBrowse in browse.go

## Question
Can an issue/PR title, body, comment, check output, or release note the attacker authored flowing through `runBrowse` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L187) be written into the repository's git config with newlines, creating an extra config section such as an alias or `core.sshCommand`?

## Target
- File/function: [pkg/cmd/browse/browse.go:187](pkg/cmd/browse/browse.go#L187) - `runBrowse`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Use a branch/remote name containing a newline and a config-looking line.
- Invariant to test: Values are validated to exclude newlines before any config write.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting a newline-bearing value is rejected.
