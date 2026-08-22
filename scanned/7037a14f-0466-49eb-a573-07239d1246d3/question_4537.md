# Q4537: extension inherits gh credentials - hasScript in http.go

## Question
Does `hasScript` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L45) pass GH_TOKEN/GH_HOST or the config path into the extension process, giving attacker code the victim's credentials?

## Target
- File/function: [pkg/cmd/extension/http.go:45](pkg/cmd/extension/http.go#L45) - `hasScript`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension that prints its environment.
- Invariant to test: Extensions receive credentials only through an explicit, user-visible mechanism.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment contents.
