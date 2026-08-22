# Q5860: enterprise/dotcom misclassification - cloneRun in clone.go

## Question
Can a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes make `cloneRun` in [pkg/cmd/gist/clone/clone.go](pkg/cmd/gist/clone/clone.go#L75) misclassify a host as enterprise or dotcom, selecting different API base paths, auth rules, or feature gates than the user intends?

## Target
- File/function: [pkg/cmd/gist/clone/clone.go:75](pkg/cmd/gist/clone/clone.go#L75) - `cloneRun`
- Entrypoint: gh gist clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a remote whose host triggers the wrong branch and observe the relaxed path.
- Invariant to test: Classification derives from the exact configured host with no remote input.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting classification for lookalike and mixed-case hosts.
