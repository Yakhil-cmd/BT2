# Q4636: refspec lets the server write local refs - NewCmdUpdate in update.go

## Question
Does the fetch performed in `NewCmdUpdate` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L66) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [pkg/cmd/skills/update/update.go:66](pkg/cmd/skills/update/update.go#L66) - `NewCmdUpdate`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
