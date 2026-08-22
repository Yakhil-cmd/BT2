# Q5055: env-provided token used against a foreign host - NewCmdSetupGit in setupgit.go

## Question
Does `NewCmdSetupGit` in [pkg/cmd/auth/setupgit/setupgit.go](pkg/cmd/auth/setupgit/setupgit.go#L27) apply a GH_TOKEN/GITHUB_TOKEN environment credential to requests whose host was derived from attacker-published repository metadata?

## Target
- File/function: [pkg/cmd/auth/setupgit/setupgit.go:27](pkg/cmd/auth/setupgit/setupgit.go#L27) - `NewCmdSetupGit`
- Entrypoint: gh auth setupgit
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a repo whose remote points at an attacker host and let a CI job running gh with GH_TOKEN operate in it.
- Invariant to test: Environment tokens are bound to the configured default host only.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with GH_TOKEN set and a foreign-host request asserting no Authorization header.
