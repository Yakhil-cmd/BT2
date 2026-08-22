# Q2482: timeout/EOF treated as approval - resolveScope in install.go

## Question
Does an EOF or closed stdin in `resolveScope` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L968) resolve to the affirmative branch?

## Target
- File/function: [pkg/cmd/skills/install/install.go:968](pkg/cmd/skills/install/install.go#L968) - `resolveScope`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Run the flow with stdin closed, as in a CI pipeline processing attacker content.
- Invariant to test: EOF is an error, never a yes.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a closed stdin asserting an error.
