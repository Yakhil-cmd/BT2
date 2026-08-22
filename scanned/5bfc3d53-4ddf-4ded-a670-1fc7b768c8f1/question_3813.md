# Q3813: refspec lets the server write local refs - (Extension).URL in extension.go

## Question
Does the fetch performed in `URL` in [pkg/cmd/extension/extension.go](pkg/cmd/extension/extension.go#L59) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [pkg/cmd/extension/extension.go:59](pkg/cmd/extension/extension.go#L59) - `(Extension).URL`
- Entrypoint: gh extension extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
