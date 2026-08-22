# Q1494: scope elevation without user consent - (GitCredentialFlow).Setup in git_credential.go

## Question
Can the flow in `Setup` in [pkg/cmd/auth/shared/git_credential.go](pkg/cmd/auth/shared/git_credential.go#L80) request or persist a broader OAuth scope set than the user approved for the operation actually being run?

## Target
- File/function: [pkg/cmd/auth/shared/git_credential.go:80](pkg/cmd/auth/shared/git_credential.go#L80) - `(GitCredentialFlow).Setup`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Trigger a path that silently refreshes with extra scopes while the user believes they authorized a read-only action.
- Invariant to test: Scope requests match the operation and are shown before authorization.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the scope list sent equals the minimum for the command.
