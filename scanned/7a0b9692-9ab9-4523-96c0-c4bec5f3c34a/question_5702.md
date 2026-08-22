# Q5702: alias argument placeholders re-split - GetSecretApp in shared.go

## Question
Does the placeholder substitution in `GetSecretApp` in [pkg/cmd/secret/shared/shared.go](pkg/cmd/secret/shared/shared.go#L66) re-split or re-interpret the substituted values, letting attacker-published names inject extra arguments?

## Target
- File/function: [pkg/cmd/secret/shared/shared.go:66](pkg/cmd/secret/shared/shared.go#L66) - `GetSecretApp`
- Entrypoint: gh secret
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger the alias with a value containing spaces/quotes from remote data.
- Invariant to test: Substituted values remain single argv elements.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test asserting argv shape after substitution.
