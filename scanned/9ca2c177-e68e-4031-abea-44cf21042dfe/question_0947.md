# Q0947: refspec lets the server write local refs - (Manager).otherBinScaffolding in manager.go

## Question
Does the fetch performed in `otherBinScaffolding` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L645) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [pkg/cmd/extension/manager.go:645](pkg/cmd/extension/manager.go#L645) - `(Manager).otherBinScaffolding`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
