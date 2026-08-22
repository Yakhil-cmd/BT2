# Q2193: enterprise/dotcom misclassification - logoutRun in logout.go

## Question
Can a hostname, OAuth/device response, or git credential-protocol input the attacker supplies make `logoutRun` in [pkg/cmd/auth/logout/logout.go](pkg/cmd/auth/logout/logout.go#L79) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [pkg/cmd/auth/logout/logout.go:79](pkg/cmd/auth/logout/logout.go#L79) - `logoutRun`
- Entrypoint: gh auth logout
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
