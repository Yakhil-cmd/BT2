# Q1486: token read by an untrusted child surface - NewCmdSetupGit in setupgit.go

## Question
Does `NewCmdSetupGit` in [pkg/cmd/auth/setupgit/setupgit.go](pkg/cmd/auth/setupgit/setupgit.go#L27) expose the token to an extension, skill, hook, or editor process whose code came from a hostname, OAuth/device response, or git credential-protocol input the attacker supplies?

## Target
- File/function: [pkg/cmd/auth/setupgit/setupgit.go:27](pkg/cmd/auth/setupgit/setupgit.go#L27) - `NewCmdSetupGit`
- Entrypoint: gh auth setupgit
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish an extension/skill the victim installs and read GH_TOKEN from its environment.
- Invariant to test: Tokens are provided only to gh's own HTTP layer and to git for matching hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the child environment built for third-party code omits token variables.
