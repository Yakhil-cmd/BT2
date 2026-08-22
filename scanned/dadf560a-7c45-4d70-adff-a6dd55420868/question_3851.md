# Q3851: extension inherits gh credentials - (cmdWithStderr).Output in run.go

## Question
Does `Output` in [internal/run/run.go](internal/run/run.go#L33) pass GH_TOKEN/GH_HOST or the config path into the extension process, giving attacker code the victim's credentials?

## Target
- File/function: [internal/run/run.go:33](internal/run/run.go#L33) - `(cmdWithStderr).Output`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension that prints its environment.
- Invariant to test: Extensions receive credentials only through an explicit, user-visible mechanism.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment contents.
