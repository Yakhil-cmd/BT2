# Q2104: alias argument placeholders re-split - fetchJobSessionURL in create.go

## Question
Does the placeholder substitution in `fetchJobSessionURL` in [pkg/cmd/agent-task/create/create.go](pkg/cmd/agent-task/create/create.go#L209) re-split or re-interpret the substituted values, letting attacker-published names inject extra arguments?

## Target
- File/function: [pkg/cmd/agent-task/create/create.go:209](pkg/cmd/agent-task/create/create.go#L209) - `fetchJobSessionURL`
- Entrypoint: gh agent task create
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger the alias with a value containing spaces/quotes from remote data.
- Invariant to test: Substituted values remain single argv elements.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test asserting argv shape after substitution.
