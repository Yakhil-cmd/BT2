# Q4922: enterprise/dotcom misclassification - newSSHCmd in ssh.go

## Question
Can codespace/API response fields and everything the codespace-side process sends back make `newSSHCmd` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L49) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:49](pkg/cmd/codespace/ssh.go#L49) - `newSSHCmd`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
