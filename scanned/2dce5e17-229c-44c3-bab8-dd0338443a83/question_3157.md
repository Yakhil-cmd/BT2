# Q3157: attacker text written into git config - IsFullyQualifiedRef in discovery.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata flowing through `IsFullyQualifiedRef` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L132) be written into the repository's git config with newlines, creating an extra config section such as an alias or `core.sshCommand`?

## Target
- File/function: [internal/skills/discovery/discovery.go:132](internal/skills/discovery/discovery.go#L132) - `IsFullyQualifiedRef`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Use a branch/remote name containing a newline and a config-looking line.
- Invariant to test: Values are validated to exclude newlines before any config write.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting a newline-bearing value is rejected.
