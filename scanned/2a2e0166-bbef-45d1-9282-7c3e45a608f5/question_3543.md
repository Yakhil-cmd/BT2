# Q3543: alias argument placeholders re-split - extractZip in copilot.go

## Question
Does the placeholder substitution in `extractZip` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L378) re-split or re-interpret the substituted values, letting attacker-published names inject extra arguments?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:378](pkg/cmd/copilot/copilot.go#L378) - `extractZip`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger the alias with a value containing spaces/quotes from remote data.
- Invariant to test: Substituted values remain single argv elements.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test asserting argv shape after substitution.
