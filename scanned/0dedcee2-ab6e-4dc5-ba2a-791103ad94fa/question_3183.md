# Q3183: refspec lets the server write local refs - NewCmdInstall in install.go

## Question
Does the fetch performed in `NewCmdInstall` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L76) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [pkg/cmd/skills/install/install.go:76](pkg/cmd/skills/install/install.go#L76) - `NewCmdInstall`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
