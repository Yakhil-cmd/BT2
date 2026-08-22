# Q3101: extension inherits gh credentials - (Extension).LatestVersion in extension.go

## Question
Does `LatestVersion` in [pkg/cmd/extension/extension.go](pkg/cmd/extension/extension.go#L116) pass GH_TOKEN/GH_HOST or the config path into the extension process, giving attacker code the victim's credentials?

## Target
- File/function: [pkg/cmd/extension/extension.go:116](pkg/cmd/extension/extension.go#L116) - `(Extension).LatestVersion`
- Entrypoint: gh extension extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension that prints its environment.
- Invariant to test: Extensions receive credentials only through an explicit, user-visible mechanism.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment contents.
