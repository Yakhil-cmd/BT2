# Q3636: device/web flow bound to the wrong host - (GitCredentialFlow).Setup in git_credential.go

## Question
Does `Setup` in [pkg/cmd/auth/shared/git_credential.go](pkg/cmd/auth/shared/git_credential.go#L80) accept the OAuth endpoints (authorize/token/device URLs) from data the attacker can influence rather than deriving them from the validated host?

## Target
- File/function: [pkg/cmd/auth/shared/git_credential.go:80](pkg/cmd/auth/shared/git_credential.go#L80) - `(GitCredentialFlow).Setup`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Serve endpoint metadata pointing token exchange at an attacker collector.
- Invariant to test: OAuth endpoints are derived from the validated host constant.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the token exchange URL host equals the login host.
