# Q2692: refspec lets the server write local refs - FormatSlice in text.go

## Question
Does the fetch performed in `FormatSlice` in [internal/text/text.go](internal/text/text.go#L97) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [internal/text/text.go:97](internal/text/text.go#L97) - `FormatSlice`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
