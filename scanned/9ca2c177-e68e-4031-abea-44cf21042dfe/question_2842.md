# Q2842: alias shadows a core command - getSecretsFromOptions in set.go

## Question
Can an alias created through `getSecretsFromOptions` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L376) override a built-in command name, so later `gh auth`/`gh api` calls run attacker-chosen arguments?

## Target
- File/function: [pkg/cmd/secret/set/set.go:376](pkg/cmd/secret/set/set.go#L376) - `getSecretsFromOptions`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish an alias file that redefines a core command.
- Invariant to test: Core command names cannot be aliased.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting rejection of core-name aliases.
