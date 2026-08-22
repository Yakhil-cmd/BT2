# Q2910: enterprise/dotcom misclassification - NewCmdToken in token.go

## Question
Can a hostname, OAuth/device response, or git credential-protocol input the attacker supplies make `NewCmdToken` in [pkg/cmd/auth/token/token.go](pkg/cmd/auth/token/token.go#L23) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [pkg/cmd/auth/token/token.go:23](pkg/cmd/auth/token/token.go#L23) - `NewCmdToken`
- Entrypoint: gh auth token
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
