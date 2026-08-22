# Q4520: extension inherits gh credentials - repoFromPath in manager.go

## Question
Does `repoFromPath` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L772) pass GH_TOKEN/GH_HOST or the config path into the extension process, giving attacker code the victim's credentials?

## Target
- File/function: [pkg/cmd/extension/manager.go:772](pkg/cmd/extension/manager.go#L772) - `repoFromPath`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension that prints its environment.
- Invariant to test: Extensions receive credentials only through an explicit, user-visible mechanism.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment contents.
