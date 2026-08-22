# Q4266: alias argument placeholders re-split - ValidAliasExpansionFunc in validations.go

## Question
Does the placeholder substitution in `ValidAliasExpansionFunc` in [pkg/cmd/alias/shared/validations.go](pkg/cmd/alias/shared/validations.go#L36) re-split or re-interpret the substituted values, letting attacker-published names inject extra arguments?

## Target
- File/function: [pkg/cmd/alias/shared/validations.go:36](pkg/cmd/alias/shared/validations.go#L36) - `ValidAliasExpansionFunc`
- Entrypoint: gh alias
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger the alias with a value containing spaces/quotes from remote data.
- Invariant to test: Substituted values remain single argv elements.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test asserting argv shape after substitution.
