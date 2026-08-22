# Q5386: refspec lets the server write local refs - detectMissingRepoDiagnostic in publish.go

## Question
Does the fetch performed in `detectMissingRepoDiagnostic` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L1022) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:1022](pkg/cmd/skills/publish/publish.go#L1022) - `detectMissingRepoDiagnostic`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
