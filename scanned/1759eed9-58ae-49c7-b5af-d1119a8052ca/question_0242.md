# Q0242: extension inherits gh credentials - checkValidExtension in command.go

## Question
Does `checkValidExtension` in [pkg/cmd/extension/command.go](pkg/cmd/extension/command.go#L694) pass GH_TOKEN/GH_HOST or the config path into the extension process, giving attacker code the victim's credentials?

## Target
- File/function: [pkg/cmd/extension/command.go:694](pkg/cmd/extension/command.go#L694) - `checkValidExtension`
- Entrypoint: gh extension command
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension that prints its environment.
- Invariant to test: Extensions receive credentials only through an explicit, user-visible mechanism.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment contents.
