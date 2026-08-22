# Q0708: alias shadows a core command - (Context).GenerateSSHKey in ssh_keys.go

## Question
Can an alias created through `GenerateSSHKey` in [pkg/ssh/ssh_keys.go](pkg/ssh/ssh_keys.go#L51) override a built-in command name, so later `gh auth`/`gh api` calls run attacker-chosen arguments?

## Target
- File/function: [pkg/ssh/ssh_keys.go:51](pkg/ssh/ssh_keys.go#L51) - `(Context).GenerateSSHKey`
- Entrypoint: gh alias import
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish an alias file that redefines a core command.
- Invariant to test: Core command names cannot be aliased.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting rejection of core-name aliases.
