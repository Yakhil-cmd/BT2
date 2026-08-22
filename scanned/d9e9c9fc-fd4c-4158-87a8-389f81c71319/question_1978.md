# Q1978: attacker text written into git config - FormatSlice in text.go

## Question
Can an issue/PR title, body, comment, check output, or release note the attacker authored flowing through `FormatSlice` in [internal/text/text.go](internal/text/text.go#L97) be written into the repository's git config with newlines, creating an extra config section such as an alias or `core.sshCommand`?

## Target
- File/function: [internal/text/text.go:97](internal/text/text.go#L97) - `FormatSlice`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Use a branch/remote name containing a newline and a config-looking line.
- Invariant to test: Values are validated to exclude newlines before any config write.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting a newline-bearing value is rejected.
