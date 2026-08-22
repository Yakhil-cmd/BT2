# Q0771: token read by an untrusted child surface - switchRun in switch.go

## Question
Does `switchRun` in [pkg/cmd/auth/switch/switch.go](pkg/cmd/auth/switch/switch.go#L77) expose the token to an extension, skill, hook, or editor process whose code came from a hostname, OAuth/device response, or git credential-protocol input the attacker supplies?

## Target
- File/function: [pkg/cmd/auth/switch/switch.go:77](pkg/cmd/auth/switch/switch.go#L77) - `switchRun`
- Entrypoint: gh auth switch
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish an extension/skill the victim installs and read GH_TOKEN from its environment.
- Invariant to test: Tokens are provided only to gh's own HTTP layer and to git for matching hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment built for third-party code omits token variables.
