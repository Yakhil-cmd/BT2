# Q2421: extension inherits gh credentials - executable in cmd.go

## Question
Does `executable` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L444) pass GH_TOKEN/GH_HOST or the config path into the extension process, giving attacker code the victim's credentials?

## Target
- File/function: [internal/ghcmd/cmd.go:444](internal/ghcmd/cmd.go#L444) - `executable`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension that prints its environment.
- Invariant to test: Extensions receive credentials only through an explicit, user-visible mechanism.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment contents.
