# Q4585: refspec lets the server write local refs - ShortRef in discovery.go

## Question
Does the fetch performed in `ShortRef` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L138) use a wildcard/attacker-influenced refspec so a hostile remote can create or overwrite local refs (including HEAD or a tracked branch)?

## Target
- File/function: [internal/skills/discovery/discovery.go:138](internal/skills/discovery/discovery.go#L138) - `ShortRef`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Serve refs that map onto the victim's local branch names.
- Invariant to test: Fetches target explicit, gh-chosen ref destinations.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the refspec is fixed and namespaced.
