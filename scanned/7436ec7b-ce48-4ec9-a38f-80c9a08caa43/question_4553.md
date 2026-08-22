# Q4553: extension inherits gh credentials - NewCmdAlias in alias.go

## Question
Does `NewCmdAlias` in [pkg/cmd/root/alias.go](pkg/cmd/root/alias.go#L54) pass GH_TOKEN/GH_HOST or the config path into the extension process, giving attacker code the victim's credentials?

## Target
- File/function: [pkg/cmd/root/alias.go:54](pkg/cmd/root/alias.go#L54) - `NewCmdAlias`
- Entrypoint: gh root alias
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension that prints its environment.
- Invariant to test: Extensions receive credentials only through an explicit, user-visible mechanism.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment contents.
