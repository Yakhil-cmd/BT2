# Q0942: extension inherits gh credentials - (Manager).upgradeGitExtension in manager.go

## Question
Does `upgradeGitExtension` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L551) pass GH_TOKEN/GH_HOST or the config path into the extension process, giving attacker code the victim's credentials?

## Target
- File/function: [pkg/cmd/extension/manager.go:551](pkg/cmd/extension/manager.go#L551) - `(Manager).upgradeGitExtension`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension that prints its environment.
- Invariant to test: Extensions receive credentials only through an explicit, user-visible mechanism.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment contents.
