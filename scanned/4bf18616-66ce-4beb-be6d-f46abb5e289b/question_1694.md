# Q1694: extension inherits gh credentials - ExtBrowse in browse.go

## Question
Does `ExtBrowse` in [pkg/cmd/extension/browse/browse.go](pkg/cmd/extension/browse/browse.go#L380) pass GH_TOKEN/GH_HOST or the config path into the extension process, giving attacker code the victim's credentials?

## Target
- File/function: [pkg/cmd/extension/browse/browse.go:380](pkg/cmd/extension/browse/browse.go#L380) - `ExtBrowse`
- Entrypoint: gh extension browse
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension that prints its environment.
- Invariant to test: Extensions receive credentials only through an explicit, user-visible mechanism.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment contents.
