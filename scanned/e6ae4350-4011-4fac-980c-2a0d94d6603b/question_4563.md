# Q4563: enterprise/dotcom misclassification - mightBeGHESUser in cmd.go

## Question
Can an extension repository, its release assets, and its manifest fields make `mightBeGHESUser` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L482) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [internal/ghcmd/cmd.go:482](internal/ghcmd/cmd.go#L482) - `mightBeGHESUser`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
