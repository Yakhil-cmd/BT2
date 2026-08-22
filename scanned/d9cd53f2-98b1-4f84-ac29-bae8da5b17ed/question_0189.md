# Q0189: token read by an untrusted child surface - authenticatedCommand in checkout.go

## Question
Does `authenticatedCommand` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L388) expose the token to an extension, skill, hook, or editor process whose code came from a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:388](pkg/cmd/pr/checkout/checkout.go#L388) - `authenticatedCommand`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish an extension/skill the victim installs and read GH_TOKEN from its environment.
- Invariant to test: Tokens are provided only to gh's own HTTP layer and to git for matching hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment built for third-party code omits token variables.
