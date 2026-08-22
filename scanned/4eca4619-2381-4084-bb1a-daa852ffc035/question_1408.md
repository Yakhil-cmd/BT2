# Q1408: alias argument placeholders re-split - importRun in import.go

## Question
Does the placeholder substitution in `importRun` in [pkg/cmd/alias/imports/import.go](pkg/cmd/alias/imports/import.go#L94) re-split or re-interpret the substituted values, letting attacker-published names inject extra arguments?

## Target
- File/function: [pkg/cmd/alias/imports/import.go:94](pkg/cmd/alias/imports/import.go#L94) - `importRun`
- Entrypoint: gh alias imports
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger the alias with a value containing spaces/quotes from remote data.
- Invariant to test: Substituted values remain single argv elements.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test asserting argv shape after substitution.
