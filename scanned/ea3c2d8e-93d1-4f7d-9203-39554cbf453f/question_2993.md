# Q2993: enterprise/dotcom misclassification - CredentialPatternFromHost in client.go

## Question
Can a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes make `CredentialPatternFromHost` in [git/client.go](git/client.go#L134) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [git/client.go:134](git/client.go#L134) - `CredentialPatternFromHost`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
